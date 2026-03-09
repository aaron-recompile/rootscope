#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


def _read_summary(path: Path) -> dict[str, Any]:
    stats: dict[str, int] = {"total": 0, "success": 0, "failed": 0}
    error_codes: list[tuple[str, int]] = []
    expected_matches: list[tuple[str, int]] = []

    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            category = (row.get("category") or "").strip()
            key = (row.get("key") or "").strip()
            value_raw = (row.get("value") or "0").strip()
            try:
                value = int(value_raw)
            except ValueError:
                value = 0

            if category == "stats" and key in stats:
                stats[key] = value
            elif category == "error_code" and key:
                error_codes.append((key, value))
            elif category == "expected_address_match" and key:
                expected_matches.append((key, value))

    return {"stats": stats, "error_codes": error_codes, "expected_matches": expected_matches}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _build_markdown(
    *,
    run_name: str,
    summary: dict[str, Any],
    records: list[dict[str, Any]],
    top_n: int,
) -> str:
    stats: dict[str, int] = summary["stats"]
    error_codes: list[tuple[str, int]] = summary["error_codes"]
    expected_matches: list[tuple[str, int]] = summary["expected_matches"]

    duration_values = [int(r.get("elapsedMs") or 0) for r in records]
    avg_ms = int(sum(duration_values) / len(duration_values)) if duration_values else 0
    max_ms = max(duration_values) if duration_values else 0

    network_counter = Counter(str(r.get("network") or "") for r in records if r.get("network"))
    depth_counter = Counter(str(r.get("depth")) for r in records if r.get("depth") is not None)

    md: list[str] = []
    md.append(f"## Batch Report: {run_name}")
    md.append("")
    md.append("### Overview")
    md.append("")
    md.append("| Metric | Value |")
    md.append("|---|---:|")
    md.append(f"| Total | {stats['total']} |")
    md.append(f"| Success | {stats['success']} |")
    md.append(f"| Failed | {stats['failed']} |")
    md.append(f"| Avg elapsed (ms) | {avg_ms} |")
    md.append(f"| Max elapsed (ms) | {max_ms} |")
    md.append("")

    if network_counter:
        md.append("### Network Distribution")
        md.append("")
        md.append("| Network | Count |")
        md.append("|---|---:|")
        for network, count in network_counter.most_common():
            md.append(f"| {network} | {count} |")
        md.append("")

    if depth_counter:
        md.append("### Depth Distribution")
        md.append("")
        md.append("| Depth | Count |")
        md.append("|---|---:|")
        for depth, count in sorted(depth_counter.items(), key=lambda x: int(x[0])):
            md.append(f"| {depth} | {count} |")
        md.append("")

    if error_codes:
        md.append("### Error Codes")
        md.append("")
        md.append("| Error Code | Count |")
        md.append("|---|---:|")
        for code, count in error_codes[:top_n]:
            md.append(f"| `{code}` | {count} |")
        md.append("")

    if expected_matches:
        md.append("### Expected Address Match")
        md.append("")
        md.append("| expectedAddressMatch | Count |")
        md.append("|---|---:|")
        for key, count in expected_matches:
            md.append(f"| {key} | {count} |")
        md.append("")

    fail_rows = [r for r in records if r.get("status") != "ok"]
    if fail_rows:
        md.append("### Failed Samples")
        md.append("")
        md.append("| Row | txid | vin | network | errorCode | errorMessage |")
        md.append("|---:|---|---:|---|---|---|")
        for r in fail_rows[:top_n]:
            txid = str(r.get("txid") or "")
            short_txid = txid[:16] + "..." if len(txid) > 16 else txid
            err_msg = str(r.get("errorMessage") or "").replace("|", "/")
            md.append(
                f"| {r.get('row')} | `{short_txid}` | {r.get('vin')} | {r.get('network')} | "
                f"`{r.get('errorCode')}` | {err_msg} |"
            )
        md.append("")

    return "\n".join(md).strip() + "\n"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="render-batch-report",
        description="Render Markdown report from RootScope batch outputs",
    )
    p.add_argument("--summary", required=True, help="Path to batch summary CSV")
    p.add_argument("--jsonl", required=True, help="Path to batch JSONL records")
    p.add_argument("--out", default="outputs/batch_report.md", help="Output markdown file")
    p.add_argument("--name", default="batch-run", help="Run name shown in report title")
    p.add_argument("--top-n", type=int, default=20, help="Top N rows for details tables")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary_path = Path(args.summary)
    jsonl_path = Path(args.jsonl)
    out_path = Path(args.out)

    if not summary_path.exists():
        raise SystemExit(f"summary file not found: {summary_path}")
    if not jsonl_path.exists():
        raise SystemExit(f"jsonl file not found: {jsonl_path}")

    summary = _read_summary(summary_path)
    records = _read_jsonl(jsonl_path)
    markdown = _build_markdown(
        run_name=args.name,
        summary=summary,
        records=records,
        top_n=max(1, int(args.top_n)),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")
    print(f"markdown report: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
