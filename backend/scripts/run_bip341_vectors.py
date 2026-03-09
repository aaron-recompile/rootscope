#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.bip341_vectors import run_bip341_script_path_vectors


def main() -> int:
    passed, total, details = run_bip341_script_path_vectors()
    print("RootScope BIP341 script-path vectors")
    print("-" * 64)
    for item in details:
        print(f"FAIL {item}")
    print("-" * 64)
    print(f"SUMMARY: {passed}/{total} PASS")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
