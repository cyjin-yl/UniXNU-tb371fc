#!/usr/bin/env python3
"""Run the Route A host checks without firmware, Apple images or device access."""

from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
raise SystemExit(subprocess.call(
    [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_route_a_*.py", "-v"],
    cwd=root))
