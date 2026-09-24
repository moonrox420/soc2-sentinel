"""Unit tests for Cryptographic Evidence Vault and Chain of Custody."""

import json
from pathlib import Path

from sentinel.vault import EvidenceVault, MerkleTree, sha256_hex


def test_merkle_tree_calculation() -> None:
    # Empty leaves produces default hash
    tree_empty = MerkleTree([])
    assert len(tree_empty.root) == 64

    # Single leaf
    leaf1 = sha256_hex("evidence_1")
    tree_single = MerkleTree([leaf1])
    assert tree_single.root == leaf1

    # Multiple leaves
    leaf2 = sha256_hex("evidence_2")
    leaf3 = sha256_hex("evidence_3")
    tree_multi = MerkleTree([leaf1, leaf2, leaf3])
    assert len(tree_multi.root) == 64
    assert tree_multi.root != leaf1


def test_evidence_vault_sealing_and_verification(tmp_path: Path) -> None:
    vault = EvidenceVault(tmp_path)

    # Initially empty chain
    res_empty = vault.verify_chain("tenant-vault-test")
    assert res_empty["valid"] is True
    assert res_empty["total_blocks"] == 0

    # Create dummy evidence runs
    run1 = tmp_path / "evidence" / "2026-09-01"
    run1_ctrl = run1 / "CC6.1"
    run1_ctrl.mkdir(parents=True)
    (run1_ctrl / "evidence.json").write_text(json.dumps({"test": 1}), encoding="utf-8")

    run2 = tmp_path / "evidence" / "2026-09-02"
    run2_ctrl = run2 / "CC6.2"
    run2_ctrl.mkdir(parents=True)
    (run2_ctrl / "evidence.json").write_text(json.dumps({"test": 2}), encoding="utf-8")

    # Seal block 0
    b0 = vault.seal_run(
        run1, tenant_id="tenant-vault-test", signatory="Security Officer"
    )
    assert b0.block_index == 0
    assert b0.previous_hash == EvidenceVault.GENESIS_HASH

    # Seal block 1
    b1 = vault.seal_run(
        run2, tenant_id="tenant-vault-test", signatory="Security Officer"
    )
    assert b1.block_index == 1
    assert b1.previous_hash == b0.block_hash

    # Verify unbroken chain
    res_verify = vault.verify_chain("tenant-vault-test")
    assert res_verify["valid"] is True
    assert res_verify["total_blocks"] == 2
    assert len(res_verify["errors"]) == 0


def test_evidence_vault_tamper_detection(tmp_path: Path) -> None:
    import pytest

    vault = EvidenceVault(tmp_path)
    empty_dir = tmp_path / "evidence" / "empty-run"
    empty_dir.mkdir(parents=True)
    with pytest.raises(ValueError, match="No valid evidence files"):
        vault.seal_run(empty_dir, tenant_id="tenant-tamper")

    run_dir = tmp_path / "evidence" / "2026-09-01" / "iam"
    run_dir.mkdir(parents=True)
    (run_dir / "report.json").write_text(json.dumps({"test": "data"}), encoding="utf-8")

    vault.seal_run(tmp_path / "evidence" / "2026-09-01", tenant_id="tenant-tamper")
    vault.seal_run(tmp_path / "evidence" / "2026-09-01", tenant_id="tenant-tamper")

    chain_file = (
        tmp_path / "tenants" / "tenant-tamper" / "vault" / "evidence_chain.jsonl"
    )
    lines = chain_file.read_text(encoding="utf-8").splitlines()

    # Tamper with block 0 payload
    block0_data = json.loads(lines[0])
    block0_data["merkle_root"] = "f" * 64
    lines[0] = json.dumps(block0_data)
    chain_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res_tampered = vault.verify_chain("tenant-tamper")
    assert res_tampered["valid"] is False
    assert any("Hash tamper detected" in err for err in res_tampered["errors"])
