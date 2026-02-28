import json
import unittest
from unittest.mock import patch

from backend.fetch_witness import FetchWitnessError, fetch_witness_by_txid


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestFetchWitness(unittest.TestCase):
    def test_invalid_txid(self) -> None:
        with self.assertRaises(FetchWitnessError) as ctx:
            fetch_witness_by_txid("abc", 0, "auto")
        self.assertEqual(ctx.exception.code, "INVALID_TXID")

    def test_extract_script_and_control_block(self) -> None:
        tx_json = {
            "vin": [
                {
                    "prevout": {
                        "scriptpubkey_type": "v1_p2tr",
                        "scriptpubkey_address": "tb1p93c4wxsr87p88jau7vru83zpk6xl0shf5ynmutd9x0gxwau3tngq9a4w3z",
                    },
                    "witness": [
                        "68656c6c6f776f726c64",
                        "a820936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af8851",
                        "c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d32faaa677cb6ad6a74bf7025e4cd03d2a82c7fb8e3c277916d7751078105cf9df",
                    ],
                }
            ]
        }

        with patch("backend.fetch_witness.urlopen", return_value=_FakeResponse(tx_json)):
            result = fetch_witness_by_txid(
                "b61857a05852482c9d5ffbb8159fc2ba1efa3dd16fe4595f121fc35878a2e430", 0, "testnet"
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["network"], "testnet")
        self.assertEqual(result["source"], "mempool")
        self.assertEqual(result["scriptHex"], tx_json["vin"][0]["witness"][1])
        self.assertEqual(result["controlBlockHex"], tx_json["vin"][0]["witness"][2])
        self.assertEqual(
            result["expectedAddress"],
            "tb1p93c4wxsr87p88jau7vru83zpk6xl0shf5ynmutd9x0gxwau3tngq9a4w3z",
        )

    def test_control_block_not_found(self) -> None:
        tx_json = {
            "vin": [{"prevout": {"scriptpubkey_type": "v1_p2tr"}, "witness": ["aa", "bb", "cc"]}]
        }
        with patch("backend.fetch_witness.urlopen", return_value=_FakeResponse(tx_json)):
            with self.assertRaises(FetchWitnessError) as ctx:
                fetch_witness_by_txid("f" * 64, 0, "mainnet")
        self.assertEqual(ctx.exception.code, "CONTROL_BLOCK_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
