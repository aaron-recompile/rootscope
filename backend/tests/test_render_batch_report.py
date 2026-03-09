import tempfile
import unittest
from pathlib import Path

from backend.scripts.render_batch_report import main


class TestRenderBatchReport(unittest.TestCase):
    def test_render_markdown_report(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            summary = tmp / "summary.csv"
            jsonl = tmp / "batch.jsonl"
            out = tmp / "report.md"

            summary.write_text(
                "category,key,value\n"
                "stats,total,2\n"
                "stats,success,1\n"
                "stats,failed,1\n"
                "error_code,INVALID_TXID,1\n"
                "expected_address_match,true,1\n",
                encoding="utf-8",
            )
            jsonl.write_text(
                '{"row":1,"status":"ok","txid":"a","vin":0,"network":"mainnet","depth":1,"elapsedMs":3}\n'
                '{"row":2,"status":"error","txid":"b","vin":1,"network":"mainnet","errorCode":"INVALID_TXID","errorMessage":"bad txid","elapsedMs":2}\n',
                encoding="utf-8",
            )

            rc = main(
                [
                    "--summary",
                    str(summary),
                    "--jsonl",
                    str(jsonl),
                    "--out",
                    str(out),
                    "--name",
                    "smoke",
                ]
            )
            self.assertEqual(rc, 0)
            text = out.read_text(encoding="utf-8")
            self.assertIn("## Batch Report: smoke", text)
            self.assertIn("| Total | 2 |", text)
            self.assertIn("| `INVALID_TXID` | 1 |", text)
            self.assertIn("| true | 1 |", text)


if __name__ == "__main__":
    unittest.main()
