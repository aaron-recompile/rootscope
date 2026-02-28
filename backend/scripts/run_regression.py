#!/usr/bin/env python3
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.analyzer import AnalysisError, analyze_taproot


@dataclass
class Case:
    name: str
    control_block: str
    script: str
    network: str
    expected_address: str
    expected_depth: int


CASES: list[Case] = [
    Case(
        name="chapter06_single_leaf",
        control_block="c150be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3",
        script="a820936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af8851",
        network="testnet",
        expected_address="tb1p53ncq9ytax924ps66z6al3wfhy6a29w8h6xfu27xem06t98zkmvsakd43h",
        expected_depth=0,
    ),
    Case(
        name="chapter07_dual_leaf",
        control_block="c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d32faaa677cb6ad6a74bf7025e4cd03d2a82c7fb8e3c277916d7751078105cf9df",
        script="a820936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af8851",
        network="testnet",
        expected_address="tb1p93c4wxsr87p88jau7vru83zpk6xl0shf5ynmutd9x0gxwau3tngq9a4w3z",
        expected_depth=1,
    ),
    Case(
        name="chapter08_four_leaf",
        control_block="c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3fe78d8523ce9603014b28739a51ef826f791aa17511e617af6dc96a8f10f659eda55197526f26fa309563b7a3551ca945c046e5b7ada957e59160d4d27f299e3",
        script="002050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3ba2084b5951609b76619a1ce7f48977b4312ebe226987166ef044bfb374ceef63af5ba5287",
        network="testnet",
        expected_address="tb1pjfdm902y2adr08qnn4tahxjvp6x5selgmvzx63yfqk2hdey02yvqjcr29q",
        expected_depth=2,
    ),
]


def run_case(case: Case) -> tuple[bool, str]:
    try:
        result = analyze_taproot(
            control_block=case.control_block,
            script=case.script,
            network=case.network,
            expected_address=case.expected_address,
        )
    except AnalysisError as exc:
        return False, f"{exc.code}: {exc.message}"
    except Exception as exc:  # pragma: no cover
        return False, f"UNEXPECTED_ERROR: {exc}"

    checks = [
        (result.address == case.expected_address, "address matches expected"),
        (result.checks.expectedAddressMatch is True, "expectedAddressMatch is true"),
        (result.cb.depth == case.expected_depth, f"depth == {case.expected_depth}"),
    ]
    failed = [msg for ok, msg in checks if not ok]
    if failed:
        return False, "; ".join(failed)

    return True, f"address={result.address}, depth={result.cb.depth}"


def main() -> int:
    print("RootScope regression: chapter06/07/08")
    print("-" * 64)
    passed = 0

    for case in CASES:
        ok, detail = run_case(case)
        status = "PASS" if ok else "FAIL"
        print(f"{status:4}  {case.name:24}  {detail}")
        if ok:
            passed += 1

    print("-" * 64)
    print(f"SUMMARY: {passed}/{len(CASES)} PASS")
    return 0 if passed == len(CASES) else 1


if __name__ == "__main__":
    raise SystemExit(main())
