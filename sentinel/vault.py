"""Cryptographic Evidence Vault & Chain of Custody (SOC 2 CC6.1, CC7.2).

Implements Merkle tree evidence hashing and immutable cryptographic ledger
chaining across historical collection runs to prove non-repudiation and evidence
integrity to SOC 2 Type II auditors.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from sentinel.auth import get_current_user
from sentinel.integrity import sha256_file
from sentinel.tenancy import get_current_tenant_id

logger = logging.getLogger("sentinel.vault")


def sha256_hex(data: bytes | str) -> str:
    """Compute SHA-256 hex digest of string or bytes."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


class MerkleTree:
    """Computes a binary Merkle tree root hash from a collection of leaf hashes."""

    def __init__(self, leaf_hashes: list[str]) -> None:
        self.leaves: list[str] = (
            list(sorted(leaf_hashes)) if leaf_hashes else ["0" * 64]
        )
        self.root: str = self._build_tree(self.leaves)

    def _build_tree(self, nodes: list[str]) -> str:
        if not nodes:
            return "0" * 64
        if len(nodes) == 1:
            return nodes[0]

        next_level: List[str] = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else left
            combined = sha256_hex(left + right)
            next_level.append(combined)

        return self._build_tree(next_level)


@dataclass
class EvidenceBlock:
    """An immutable record in the audit evidence chain."""

    block_index: int
    timestamp: str
    tenant_id: str
    evidence_date: str
    merkle_root: str
    previous_hash: str
    block_hash: str
    collector_count: int
    signatory: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def calculate_hash(
        cls,
        block_index: int,
        timestamp: str,
        tenant_id: str,
        evidence_date: str,
        merkle_root: str,
        previous_hash: str,
        collector_count: int,
        signatory: str,
    ) -> str:
        payload = f"{block_index}|{timestamp}|{tenant_id}|{evidence_date}|{merkle_root}|{previous_hash}|{collector_count}|{signatory}"
        return sha256_hex(payload)


class EvidenceVault:
    """Manages evidence ledger chaining and cryptographic audit verification."""

    GENESIS_HASH = "0" * 64

    def __init__(self, base_root: Path | None = None) -> None:
        self.base_root = base_root or Path.cwd()
        self.evidence_dir = self.base_root / "evidence"

    def _get_chain_file(self, tenant_id: str) -> Path:
        if tenant_id == "default":
            vault_dir = self.base_root / "vault"
        else:
            vault_dir = self.base_root / "tenants" / tenant_id / "vault"
        vault_dir.mkdir(parents=True, exist_ok=True)
        return vault_dir / "evidence_chain.jsonl"

    def read_chain(self, tenant_id: Optional[str] = None) -> List[EvidenceBlock]:
        """Read and parse the full evidence ledger for a tenant."""
        tid = tenant_id or get_current_tenant_id()
        chain_file = self._get_chain_file(tid)
        if not chain_file.exists():
            return []

        blocks: List[EvidenceBlock] = []
        for line in chain_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                blocks.append(EvidenceBlock(**data))
            except Exception as ex:
                logger.warning("Corrupt block in evidence chain: %s (%s)", line, ex)
        return blocks

    def seal_run(
        self,
        evidence_date_dir: Path | str,
        tenant_id: Optional[str] = None,
        signatory: Optional[str] = None,
    ) -> EvidenceBlock:
        """Calculate Merkle root of an evidence run and append an immutable block to the chain."""
        tid = tenant_id or get_current_tenant_id()
        signer = signatory or get_current_user().user_id
        chain = self.read_chain(tid)

        prev_hash = chain[-1].block_hash if chain else self.GENESIS_HASH
        block_index = len(chain)

        date_path = Path(evidence_date_dir)
        if not date_path.exists():
            alt_path = self.evidence_dir / evidence_date_dir
            if alt_path.exists():
                date_path = alt_path

        # Collect hashes of all evidence JSON files (report.json or evidence.json)
        leaf_hashes: List[str] = []
        collector_count = 0
        if date_path.exists():
            for sub in sorted(date_path.iterdir()):
                if sub.is_dir() and sub.name != "manifests":
                    rep_file = sub / "report.json"
                    if not rep_file.exists():
                        rep_file = sub / "evidence.json"
                    if rep_file.exists():
                        leaf_hashes.append(sha256_file(rep_file))
                        collector_count += 1
            if collector_count == 0:
                for json_file in sorted(date_path.rglob("*.json")):
                    if json_file.name in {"report.json", "evidence.json"}:
                        leaf_hashes.append(sha256_file(json_file))
                        collector_count += 1

        if collector_count == 0:
            raise ValueError(
                f"No valid evidence files (report.json or evidence.json) found to seal in {evidence_date_dir}"
            )

        merkle_root = MerkleTree(leaf_hashes).root
        timestamp = datetime.now(timezone.utc).isoformat()
        evidence_date = date_path.name

        block_hash = EvidenceBlock.calculate_hash(
            block_index=block_index,
            timestamp=timestamp,
            tenant_id=tid,
            evidence_date=evidence_date,
            merkle_root=merkle_root,
            previous_hash=prev_hash,
            collector_count=collector_count,
            signatory=signer,
        )

        block = EvidenceBlock(
            block_index=block_index,
            timestamp=timestamp,
            tenant_id=tid,
            evidence_date=evidence_date,
            merkle_root=merkle_root,
            previous_hash=prev_hash,
            block_hash=block_hash,
            collector_count=collector_count,
            signatory=signer,
            details={"leaf_count": len(leaf_hashes)},
        )

        chain_file = self._get_chain_file(tid)
        with chain_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(block.to_dict()) + "\n")

        return block

    def verify_chain(self, tenant_id: Optional[str] = None) -> dict[str, Any]:
        """Verify the cryptographic continuity and hash integrity of the entire chain."""
        tid = tenant_id or get_current_tenant_id()
        chain = self.read_chain(tid)
        if not chain:
            return {"valid": True, "total_blocks": 0, "message": "Chain is empty"}

        errors: List[str] = []
        expected_prev_hash = self.GENESIS_HASH

        for idx, block in enumerate(chain):
            # Check block index continuity
            if block.block_index != idx:
                errors.append(
                    f"Block index mismatch at position {idx}: got {block.block_index}"
                )

            # Check previous hash linkage
            if block.previous_hash != expected_prev_hash:
                errors.append(
                    f"Broken chain linkage at block {idx}: expected prev_hash '{expected_prev_hash}', got '{block.previous_hash}'"
                )

            # Recalculate block hash
            recomputed = EvidenceBlock.calculate_hash(
                block_index=block.block_index,
                timestamp=block.timestamp,
                tenant_id=block.tenant_id,
                evidence_date=block.evidence_date,
                merkle_root=block.merkle_root,
                previous_hash=block.previous_hash,
                collector_count=block.collector_count,
                signatory=block.signatory,
            )
            if block.block_hash != recomputed:
                errors.append(
                    f"Hash tamper detected at block {idx}: recorded '{block.block_hash}', calculated '{recomputed}'"
                )

            expected_prev_hash = block.block_hash

        return {
            "valid": len(errors) == 0,
            "total_blocks": len(chain),
            "latest_block_hash": chain[-1].block_hash if chain else None,
            "errors": errors,
        }
