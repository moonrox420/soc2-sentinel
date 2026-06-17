from __future__ import annotations

import csv
import logging
import re
from pathlib import Path

from sentinel.errors import ValidationError
from sentinel.paths import install_root

logger = logging.getLogger("sentinel")

_CONTROL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ARTIFACT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RESERVED_NAMES = frozenset({".", "..", "CON", "PRN", "AUX", "NUL"})

_known_controls: set[str] | None = None


def _load_known_controls() -> set[str]:
    global _known_controls
    if _known_controls is not None:
        return _known_controls
    known: set[str] = set()
    matrix = install_root() / "data" / "controls-matrix.csv"
    if matrix.exists():
        with matrix.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                cid = (row.get("control_id") or row.get("Control ID") or "").strip()
                if cid:
                    known.add(cid)
    cmmc = install_root() / "data" / "cmmc-l2-controls-110.csv"
    if cmmc.exists():
        with cmmc.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                cid = (row.get("Practice ID") or row.get("practice_id") or "").strip()
                if cid:
                    known.add(cid)
    known.update({"CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC7.2", "CC8.1", "C1.1", "C1.2", "C1.3", "C1.4", "A1.2", "A1.3", "ZT-1"})
    _known_controls = known
    return known


def sanitize_control_id(control_id: str, *, strict_allowlist: bool = False) -> str:
    value = (control_id or "").strip()
    if not value:
        raise ValidationError("control_id is required")
    if ".." in value or "/" in value or "\\" in value or ":" in value:
        raise ValidationError(f"control_id contains unsafe path characters: {control_id!r}")
    if not _CONTROL_ID_PATTERN.match(value):
        raise ValidationError(f"control_id has invalid format: {control_id!r}")
    if value.upper() in _RESERVED_NAMES:
        raise ValidationError(f"control_id is reserved: {control_id!r}")
    if strict_allowlist:
        known = _load_known_controls()
        if value not in known:
            raise ValidationError(f"control_id not in known controls list: {control_id!r}")
    elif value not in _load_known_controls():
        logger.warning("Unknown control_id (allowed): %s", value)
    return value


def sanitize_artifact_name(name: str) -> str:
    value = (name or "").strip()
    if not value:
        raise ValidationError("artifact name is required")
    if ".." in value or "/" in value or "\\" in value:
        raise ValidationError(f"artifact name contains path separators: {name!r}")
    if not _ARTIFACT_PATTERN.match(value):
        raise ValidationError(f"artifact name has invalid format: {name!r}")
    if value.upper() in _RESERVED_NAMES:
        raise ValidationError(f"artifact name is reserved: {name!r}")
    return value


def resolve_safe_output_base(base: Path | None) -> Path:
    root = (base or Path.cwd()).resolve()
    if not root.exists():
        raise ValidationError(f"output base does not exist: {root}")
    if not root.is_dir():
        raise ValidationError(f"output base is not a directory: {root}")
    probe = root / ".sentinel_write_probe"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        raise ValidationError(f"output base is not writable: {root}") from exc
    return root