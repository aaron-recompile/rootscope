import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from backend.cli import main
from backend.fetch_witness import FetchWitnessError


class TestCli(unittest.TestCase):
    def test_tx_json_output(self) -> None:
        fetch_payload = {
            "ok": True,
            "source": "mempool",
            "network": "testnet",
            "txid": "a" * 64,
            "vin": 0,
            "scriptHex": "51",
            "controlBlockHex": "c1" + ("11" * 32),
            "expectedAddress": "tb1ptestxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "witnessStack": ["51", "c1" + ("11" * 32)],
            "notes": [],
        }
        analysis_payload = {
            "cb": {
                "raw": fetch_payload["controlBlockHex"],
                "versionByte": 193,
                "leafVersion": 192,
                "parity": 1,
                "internalKey": "11" * 32,
                "depth": 0,
                "path": [],
            },
            "steps": [],
            "leafHex": "aa" * 32,
            "merkleRootHex": "bb" * 32,
            "tweakHex": "cc" * 32,
            "outputKey": "dd" * 32,
            "computedParity": 1,
            "parityMatch": True,
            "address": "tb1ptestxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "checks": {
                "expectedProvided": True,
                "expectedAddressMatch": True,
                "expectedAddressReason": None,
                "parityMatch": True,
            },
        }

        class _Resp:
            def model_dump(self):
                return analysis_payload

        buf = io.StringIO()
        with patch("backend.cli.fetch_witness_by_txid", return_value=fetch_payload), patch(
            "backend.cli.analyze_taproot", return_value=_Resp()
        ), redirect_stdout(buf):
            rc = main(["tx", "a" * 64, "--json"])

        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue().strip())
        self.assertIn("fetch", payload)
        self.assertIn("analysis", payload)

    def test_batch_csv_partial_fail(self) -> None:
        class _Resp:
            def __init__(self, payload):
                self._payload = payload

            def model_dump(self):
                return self._payload

        analysis_payload = {
            "cb": {
                "raw": "c1" + ("11" * 32),
                "versionByte": 193,
                "leafVersion": 192,
                "parity": 1,
                "internalKey": "11" * 32,
                "depth": 0,
                "path": [],
            },
            "steps": [],
            "leafHex": "aa" * 32,
            "merkleRootHex": "bb" * 32,
            "tweakHex": "cc" * 32,
            "outputKey": "dd" * 32,
            "computedParity": 1,
            "parityMatch": True,
            "address": "tb1ptestxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "checks": {
                "expectedProvided": False,
                "expectedAddressMatch": None,
                "expectedAddressReason": None,
                "parityMatch": True,
            },
        }

        def _fake_fetch(txid: str, vin: int, network: str):
            if txid == ("a" * 64):
                return {
                    "ok": True,
                    "source": "mempool",
                    "network": "testnet",
                    "txid": txid,
                    "vin": vin,
                    "scriptHex": "51",
                    "controlBlockHex": "c1" + ("11" * 32),
                    "expectedAddress": None,
                    "witnessStack": [],
                    "notes": [],
                }
            raise FetchWitnessError("INVALID_TXID", 400, "txid must be 64 hex chars")

        with tempfile.TemporaryDirectory() as td:
            csv_path = Path(td) / "input.csv"
            out_path = Path(td) / "batch.jsonl"
            summary_path = Path(td) / "summary.csv"
            csv_path.write_text(
                "txid,vin,network\n"
                + ("a" * 64)
                + ",0,testnet\n"
                + "123,0,testnet\n",
                encoding="utf-8",
            )

            with patch("backend.cli.fetch_witness_by_txid", side_effect=_fake_fetch), patch(
                "backend.cli.analyze_taproot", return_value=_Resp(analysis_payload)
            ):
                rc = main(
                    [
                        "batch",
                        "--input-csv",
                        str(csv_path),
                        "--out",
                        str(out_path),
                        "--summary",
                        str(summary_path),
                    ]
                )

            self.assertEqual(rc, 4)
            lines = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[0]["status"], "ok")
            self.assertEqual(lines[1]["status"], "error")
            self.assertEqual(lines[1]["errorCode"], "INVALID_TXID")
            summary = summary_path.read_text(encoding="utf-8")
            self.assertIn("stats,total,2", summary)
            self.assertIn("stats,failed,1", summary)

    def test_batch_expected_match_stats(self) -> None:
        class _Resp:
            def __init__(self, payload):
                self._payload = payload

            def model_dump(self):
                return self._payload

        def _fake_analyze(*, control_block, script, network, expected_address):
            match = expected_address == "bc1pexpectedgood"
            payload = {
                "cb": {
                    "raw": control_block,
                    "versionByte": 193,
                    "leafVersion": 192,
                    "parity": 1,
                    "internalKey": "11" * 32,
                    "depth": 0,
                    "path": [],
                },
                "steps": [],
                "leafHex": "aa" * 32,
                "merkleRootHex": "bb" * 32,
                "tweakHex": "cc" * 32,
                "outputKey": "dd" * 32,
                "computedParity": 1,
                "parityMatch": True,
                "address": "bc1pcomputed",
                "checks": {
                    "expectedProvided": expected_address is not None,
                    "expectedAddressMatch": match if expected_address is not None else None,
                    "expectedAddressReason": None if match else "mismatch",
                    "parityMatch": True,
                },
            }
            return _Resp(payload)

        with tempfile.TemporaryDirectory() as td:
            csv_path = Path(td) / "input.csv"
            out_path = Path(td) / "batch.jsonl"
            summary_path = Path(td) / "summary.csv"
            csv_path.write_text(
                "txid,vin,network,scriptHex,controlBlockHex,expected\n"
                + ("a" * 64)
                + ",0,mainnet,51,"
                + ("c1" + ("11" * 32))
                + ",bc1pexpectedgood\n"
                + ("b" * 64)
                + ",0,mainnet,51,"
                + ("c1" + ("11" * 32))
                + ",bc1pexpectedbad\n",
                encoding="utf-8",
            )

            with patch("backend.cli.analyze_taproot", side_effect=_fake_analyze):
                rc = main(
                    [
                        "batch",
                        "--input-csv",
                        str(csv_path),
                        "--out",
                        str(out_path),
                        "--summary",
                        str(summary_path),
                    ]
                )

            self.assertEqual(rc, 0)
            summary = summary_path.read_text(encoding="utf-8")
            self.assertIn("expected_address_match,true,1", summary)
            self.assertIn("expected_address_match,false,1", summary)

    def test_batch_sqlite_join_expected_query(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out_path = Path(td) / "batch.jsonl"
            summary_path = Path(td) / "summary.csv"
            with patch("backend.cli._iter_sqlite_rows", return_value=[]) as mocked_rows:
                rc = main(
                    [
                        "batch",
                        "--input-sqlite",
                        "/tmp/fake.db",
                        "--sqlite-join-expected",
                        "--out",
                        str(out_path),
                        "--summary",
                        str(summary_path),
                    ]
                )

            self.assertEqual(rc, 0)
            called_query = mocked_rows.call_args[0][1]
            self.assertIn("o.address AS expected", called_query)
            self.assertIn("LEFT JOIN p2tr_outputs", called_query)


if __name__ == "__main__":
    unittest.main()
