import unittest

from backend.bip341_vectors import run_bip341_script_path_vectors


class TestBIP341Vectors(unittest.TestCase):
    def test_bip341_script_path_vectors(self) -> None:
        passed, total, details = run_bip341_script_path_vectors()
        self.assertEqual(
            passed,
            total,
            msg=f"BIP341 script-path vectors failed: {'; '.join(details)}",
        )


if __name__ == "__main__":
    unittest.main()
