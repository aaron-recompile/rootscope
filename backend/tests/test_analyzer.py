import unittest

from backend.analyzer import AnalysisError, analyze_taproot, parse_control_block
from backend.crypto import N, bech32m_encode, lift_x, point_add, point_mul, tap_branch_hash, tap_leaf_hash, tap_tweak_hash


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

    def test_unbalanced_three_leaf_tree_consistent_output_key(self) -> None:
        # Unbalanced tree shape: root = TapBranch(TapBranch(A, B), C)
        leaf_version = 0xC0
        script_a = bytes.fromhex("51")  # OP_1
        script_b = bytes.fromhex("52")  # OP_2
        script_c = bytes.fromhex("53")  # OP_3

        leaf_a = tap_leaf_hash(leaf_version, script_a)
        leaf_b = tap_leaf_hash(leaf_version, script_b)
        leaf_c = tap_leaf_hash(leaf_version, script_c)
        branch_ab = tap_branch_hash(leaf_a, leaf_b)
        merkle_root = tap_branch_hash(branch_ab, leaf_c)

        internal_key = bytes.fromhex("50be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d3")
        tweak = tap_tweak_hash(internal_key, merkle_root)
        tweak_int = int.from_bytes(tweak, "big")
        self.assertLess(tweak_int, N)

        p = lift_x(int.from_bytes(internal_key, "big"))
        self.assertIsNotNone(p)
        q = point_add(p, point_mul(tweak_int))
        self.assertIsNotNone(q)
        out_x, out_y = q  # type: ignore[misc]
        parity = out_y & 1
        expected_address = bech32m_encode("tb", 1, out_x.to_bytes(32, "big"))

        # Control block for revealing leaf A: path [leaf_b, leaf_c], depth=2.
        control_block_a = (bytes([leaf_version | parity]) + internal_key + leaf_b + leaf_c).hex()
        # Control block for revealing leaf C: path [branch_ab], depth=1.
        control_block_c = (bytes([leaf_version | parity]) + internal_key + branch_ab).hex()

        result_a = analyze_taproot(
            control_block=control_block_a,
            script=script_a.hex(),
            network="testnet",
            expected_address=expected_address,
        )
        result_c = analyze_taproot(
            control_block=control_block_c,
            script=script_c.hex(),
            network="testnet",
            expected_address=expected_address,
        )

        self.assertEqual(result_a.cb.depth, 2)
        self.assertEqual(result_c.cb.depth, 1)
        self.assertEqual(result_a.merkleRootHex, merkle_root.hex())
        self.assertEqual(result_c.merkleRootHex, merkle_root.hex())
        self.assertEqual(result_a.outputKey, result_c.outputKey)
        self.assertEqual(result_a.address, result_c.address)
        self.assertTrue(result_a.checks.expectedAddressMatch)
        self.assertTrue(result_c.checks.expectedAddressMatch)


if __name__ == "__main__":
    unittest.main()
