from __future__ import annotations

import sys
from pathlib import Path


def install_root() -> Path:
    """Toolkit root: repo root in dev, parent of bin/ when frozen."""
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        return exe.parent.parent if exe.parent.name == "bin" else exe.parent
    return Path(__file__).resolve().parent.parent