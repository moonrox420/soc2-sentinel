#!/usr/bin/env python3
import subprocess
import sys

raise SystemExit(
    subprocess.call([sys.executable, "-m", "sentinel.cli", "run", "iam_access_review", *sys.argv[1:]])
)