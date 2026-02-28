import unittest

from backend.analyzer import AnalysisError, analyze_taproot, parse_control_block
from backend.crypto import tap_branch_hash


class TestAnalyzer(unittest.TestCase):
    def test_parse_control_block_lengths(self) -> None:
        # 33 bytes (single leaf)
        cb33 = "c1" + ("11" * 32)
        parsed, siblings, _ = parse_control_block(cb33)
        self.assertEqual(parsed.depth, 0)
        self.assertEqual(len(siblings), 0)

        # 65 bytes (dual leaf)
        cb65 = "c0" + ("22" * 32) + ("33" * 32)
        parsed, siblings, _ = parse_control_block(cb65)
        self.assertEqual(parsed.depth, 1)
        self.assertEqual(len(siblings), 1)

        # 97 bytes (four-leaf depth=2)
        cb97 = "c1" + ("44" * 32) + ("55" * 32) + ("66" * 32)
        parsed, siblings, _ = parse_control_block(cb97)
        self.assertEqual(parsed.depth, 2)
        self.assertEqual(len(siblings), 2)

    def test_invalid_control_block_length(self) -> None:
        with self.assertRaises(AnalysisError):
            parse_control_block("00" * 32)
        with self.assertRaises(AnalysisError):
            parse_control_block("00" * 34)

    def test_tap_branch_commutative_by_sorting(self) -> None:
        a = bytes.fromhex("11" * 32)
        b = bytes.fromhex("aa" * 32)
        self.assertEqual(tap_branch_hash(a, b), tap_branch_hash(b, a))

    def test_chapter06_single_leaf_vector(self) -> None:
        result = analyze_taproot(
            control_block="c150be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3",
            script="a820936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af8851",
            network="testnet",
            expected_address="tb1p53ncq9ytax924ps66z6al3wfhy6a29w8h6xfu27xem06t98zkmvsakd43h",
        )
        self.assertEqual(result.address, "tb1p53ncq9ytax924ps66z6al3wfhy6a29w8h6xfu27xem06t98zkmvsakd43h")
        self.assertTrue(result.checks.expectedAddressMatch)

    def test_chapter07_dual_leaf_vector(self) -> None:
        result = analyze_taproot(
            control_block="c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d32faaa677cb6ad6a74bf7025e4cd03d2a82c7fb8e3c277916d7751078105cf9df",
            script="a820936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af8851",
            network="testnet",
            expected_address="tb1p93c4wxsr87p88jau7vru83zpk6xl0shf5ynmutd9x0gxwau3tngq9a4w3z",
        )
        self.assertEqual(result.address, "tb1p93c4wxsr87p88jau7vru83zpk6xl0shf5ynmutd9x0gxwau3tngq9a4w3z")
        self.assertTrue(result.checks.expectedAddressMatch)

    def test_chapter08_four_leaf_vector(self) -> None:
        # Values from RootScope example aligned with mastering-taproot chapter08 flow.
        result = analyze_taproot(
            control_block="c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3fe78d8523ce9603014b28739a51ef826f791aa17511e617af6dc96a8f10f659eda55197526f26fa309563b7a3551ca945c046e5b7ada957e59160d4d27f299e3",
            script="002050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3ba2084b5951609b76619a1ce7f48977b4312ebe226987166ef044bfb374ceef63af5ba5287",
            network="testnet",
            expected_address="tb1pjfdm902y2adr08qnn4tahxjvp6x5selgmvzx63yfqk2hdey02yvqjcr29q",
        )
        self.assertEqual(result.address, "tb1pjfdm902y2adr08qnn4tahxjvp6x5selgmvzx63yfqk2hdey02yvqjcr29q")
        self.assertTrue(result.checks.expectedAddressMatch)


if __name__ == "__main__":
    unittest.main()
