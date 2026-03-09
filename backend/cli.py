from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

from .analyzer import AnalysisError, analyze_taproot
from .fetch_witness import FetchWitnessError, fetch_witness_by_txid

DEFAULT_SQLITE_QUERY = (
    "SELECT spend_txid AS txid, input_index AS vin, network, "
    "leaf_script_hex AS scriptHex, control_block_hex AS controlBlockHex "
    "FROM script_path_spends ORDER BY id DESC"
)

DEFAULT_SQLITE_QUERY_WITH_EXPECTED = (
    "SELECT s.spend_txid AS txid, s.input_index AS vin, s.network, "
    "s.leaf_script_hex AS scriptHex, s.control_block_hex AS controlBlockHex, "
    "o.address AS expected "
    "FROM script_path_spends s "
    "LEFT JOIN p2tr_outputs o "
    "ON o.network = s.network AND o.outpoint = s.prev_outpoint "
    "ORDER BY s.id DESC"
)


def _print_tx_human(fetch_payload: dict[str, Any], analysis_payload: dict[str, Any]) -> None:
    cb = analysis_payload["cb"]
    checks = analysis_payload["checks"]

    print("RootScope CLI")
    print("-" * 64)
    print(f"txid:      {fetch_payload['txid']}")
    print(f"vin:       {fetch_payload['vin']}")
    print(f"source:    {fetch_payload['source']}")
    print(f"network:   {fetch_payload['network']}")
    print()
    print("Witness Extraction")
    print(f"- script bytes:        {len(fetch_payload['scriptHex']) // 2}")
    print(f"- control block bytes: {len(fetch_payload['controlBlockHex']) // 2}")
    print(f"- depth:               {cb['depth']}")
    print()
    print("Taproot Reconstruction")
    print(f"- merkle root:   {analysis_payload['merkleRootHex']}")
    print(f"- tweak:         {analysis_payload['tweakHex']}")
    print(f"- output key:    {analysis_payload['outputKey']}")
    print(f"- address:       {analysis_payload['address']}")
    print(f"- parity match:  {analysis_payload['parityMatch']}")
    print()
    if checks.get("expectedProvided"):
        print("Expected Address Check")
        print(f"- expected:      {fetch_payload.get('expectedAddress')}")
        print(f"- match:         {checks.get('expectedAddressMatch')}")
        reason = checks.get("expectedAddressReason")
        if reason:
            print(f"- reason:        {reason}")
        print()
    print("Result: OK")


def run_tx(args: argparse.Namespace) -> int:
    try:
        fetch_payload = fetch_witness_by_txid(
            txid=args.txid,
            vin=args.vin,
            network=args.network,
        )
    except FetchWitnessError as exc:
        print(f"[fetch-witness] {exc.code}: {exc.message}", file=sys.stderr)
        return 2

    expected_address = args.expected or fetch_payload.get("expectedAddress")
    try:
        analysis = analyze_taproot(
            control_block=fetch_payload["controlBlockHex"],
            script=fetch_payload["scriptHex"],
            network=fetch_payload["network"],
            expected_address=expected_address,
        )
    except AnalysisError as exc:
        print(f"[analyze] {exc.code}: {exc.message}", file=sys.stderr)
        return 3

    analysis_payload = analysis.model_dump()
    if args.json:
        print(
            json.dumps(
                {
                    "fetch": fetch_payload,
                    "analysis": analysis_payload,
                },
                ensure_ascii=True,
            )
        )
    else:
        _print_tx_human(fetch_payload, analysis_payload)
    return 0


def _normalize_network(value: str | None, default_network: str) -> str:
    if not value:
        return default_network
    raw = value.strip().lower()
    if raw in {"testnet", "testnet3"}:
        return "testnet"
    if raw in {"mainnet", "bitcoin"}:
        return "mainnet"
    return default_network


def _iter_csv_rows(path: str) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV has no header row")
        return [dict(r) for r in reader]


def _iter_sqlite_rows(db_path: str, query: str, limit: int | None = None) -> list[dict[str, Any]]:
    sql = query.strip().rstrip(";")
    if limit is not None:
        sql = f"SELECT * FROM ({sql}) LIMIT {int(limit)}"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(sql).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _resolve_expected(row: dict[str, Any]) -> str | None:
    for key in ("expected", "expectedAddress", "expected_address"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _build_record_base(row_num: int, row: dict[str, Any], default_network: str) -> dict[str, Any]:
    txid = str(row.get("txid", "") or "").strip().lower()
    vin_raw = row.get("vin", row.get("input_index", 0))
    try:
        vin = int(vin_raw)
    except (TypeError, ValueError):
        vin = 0

    record = {
        "row": row_num,
        "status": "error",
        "errorCode": None,
        "errorMessage": None,
        "txid": txid,
        "vin": vin,
        "network": _normalize_network(str(row.get("network", "") or ""), default_network),
        "source": None,
        "depth": None,
        "address": None,
        "merkleRootHex": None,
        "tweakHex": None,
        "parityMatch": None,
        "expectedAddressMatch": None,
        "elapsedMs": None,
        "tag": row.get("tag"),
    }
    return record


def _run_batch_row(row_num: int, row: dict[str, Any], default_network: str) -> dict[str, Any]:
    t0 = time.perf_counter()
    record = _build_record_base(row_num, row, default_network)
    expected_address = _resolve_expected(row)

    script_hex = str(row.get("scriptHex", row.get("leaf_script_hex", "")) or "").strip().lower()
    control_block_hex = str(row.get("controlBlockHex", row.get("control_block_hex", "")) or "").strip().lower()

    try:
        if script_hex and control_block_hex:
            source = "input"
        else:
            fetched = fetch_witness_by_txid(
                txid=record["txid"],
                vin=record["vin"],
                network=record["network"],
            )
            script_hex = fetched["scriptHex"]
            control_block_hex = fetched["controlBlockHex"]
            source = str(fetched.get("source") or "fetch")
            if not expected_address:
                fetched_expected = fetched.get("expectedAddress")
                if isinstance(fetched_expected, str) and fetched_expected.strip():
                    expected_address = fetched_expected.strip()
            record["network"] = fetched["network"]

        analysis = analyze_taproot(
            control_block=control_block_hex,
            script=script_hex,
            network=record["network"],
            expected_address=expected_address,
        )
        payload = analysis.model_dump()
        record["status"] = "ok"
        record["source"] = source
        record["depth"] = payload["cb"]["depth"]
        record["address"] = payload["address"]
        record["merkleRootHex"] = payload["merkleRootHex"]
        record["tweakHex"] = payload["tweakHex"]
        record["parityMatch"] = payload["parityMatch"]
        record["expectedAddressMatch"] = payload["checks"]["expectedAddressMatch"]
    except FetchWitnessError as exc:
        record["errorCode"] = exc.code
        record["errorMessage"] = exc.message
    except AnalysisError as exc:
        record["errorCode"] = exc.code
        record["errorMessage"] = exc.message
    except Exception as exc:  # pragma: no cover
        record["errorCode"] = "INTERNAL_ERROR"
        record["errorMessage"] = str(exc)
    finally:
        record["elapsedMs"] = int((time.perf_counter() - t0) * 1000)
    return record


def _write_summary_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    total = len(rows)
    success = sum(1 for r in rows if r["status"] == "ok")
    failed = total - success
    code_counter = Counter(str(r["errorCode"]) for r in rows if r["status"] != "ok" and r["errorCode"])
    expected_counter = Counter(
        str(r["expectedAddressMatch"]).lower()
        for r in rows
        if r["status"] == "ok" and r.get("expectedAddressMatch") is not None
    )

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["category", "key", "value"])
        writer.writeheader()
        writer.writerow({"category": "stats", "key": "total", "value": total})
        writer.writerow({"category": "stats", "key": "success", "value": success})
        writer.writerow({"category": "stats", "key": "failed", "value": failed})
        for code, count in code_counter.most_common():
            writer.writerow({"category": "error_code", "key": code, "value": count})
        for key, count in expected_counter.most_common():
            writer.writerow({"category": "expected_address_match", "key": key, "value": count})


def run_batch(args: argparse.Namespace) -> int:
    if bool(args.input_csv) == bool(args.input_sqlite):
        print("Provide exactly one of --input-csv or --input-sqlite", file=sys.stderr)
        return 1
    if args.sqlite_join_expected and args.input_csv:
        print("--sqlite-join-expected can only be used with --input-sqlite", file=sys.stderr)
        return 1
    if args.sqlite_join_expected and args.query != DEFAULT_SQLITE_QUERY:
        print("--sqlite-join-expected cannot be combined with a custom --query", file=sys.stderr)
        return 1

    try:
        if args.input_csv:
            source_rows = _iter_csv_rows(args.input_csv)
        else:
            sql_query = DEFAULT_SQLITE_QUERY_WITH_EXPECTED if args.sqlite_join_expected else args.query
            source_rows = _iter_sqlite_rows(args.input_sqlite, sql_query, args.limit)
    except Exception as exc:
        print(f"[batch] INPUT_ERROR: {exc}", file=sys.stderr)
        return 2

    if args.input_csv and args.limit is not None:
        source_rows = source_rows[: args.limit]

    out_path = Path(args.out)
    summary_path = Path(args.summary)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    with out_path.open("w", encoding="utf-8") as f:
        for idx, row in enumerate(source_rows, start=1):
            rec = _run_batch_row(idx, row, args.default_network)
            records.append(rec)
            f.write(json.dumps(rec, ensure_ascii=True) + "\n")
            if args.fail_fast and rec["status"] != "ok":
                break

    _write_summary_csv(summary_path, records)

    success = sum(1 for r in records if r["status"] == "ok")
    failed = len(records) - success
    exp_true = sum(1 for r in records if r["status"] == "ok" and r.get("expectedAddressMatch") is True)
    exp_false = sum(1 for r in records if r["status"] == "ok" and r.get("expectedAddressMatch") is False)
    exp_missing = sum(1 for r in records if r["status"] == "ok" and r.get("expectedAddressMatch") is None)
    print("RootScope Batch v0")
    print("-" * 64)
    print(f"rows processed: {len(records)}")
    print(f"success:        {success}")
    print(f"failed:         {failed}")
    print(f"expected=true:  {exp_true}")
    print(f"expected=false: {exp_false}")
    print(f"expected=null:  {exp_missing}")
    print(f"jsonl:          {out_path}")
    print(f"summary:        {summary_path}")
    return 0 if failed == 0 else 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rootscope",
        description="RootScope CLI for Taproot script-path analysis",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    tx = sub.add_parser("tx", help="Analyze a transaction input by txid + vin")
    tx.add_argument("txid", help="Transaction ID (64-char hex)")
    tx.add_argument("--vin", type=int, default=0, help="Input index (default: 0)")
    tx.add_argument(
        "--network",
        choices=["auto", "testnet", "mainnet"],
        default="auto",
        help="Network lookup mode (default: auto)",
    )
    tx.add_argument(
        "--expected",
        default=None,
        help="Override expected Taproot address (optional)",
    )
    tx.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON output",
    )
    tx.set_defaults(_handler=run_tx)

    batch = sub.add_parser("batch", help="Batch analysis from CSV or SQLite inputs")
    batch.add_argument("--input-csv", default=None, help="CSV input path")
    batch.add_argument("--input-sqlite", default=None, help="SQLite DB path")
    batch.add_argument(
        "--query",
        default=DEFAULT_SQLITE_QUERY,
        help="SQL query for --input-sqlite mode",
    )
    batch.add_argument(
        "--sqlite-join-expected",
        action="store_true",
        help="Use built-in SQLite query with LEFT JOIN p2tr_outputs to populate expected",
    )
    batch.add_argument("--limit", type=int, default=None, help="Process only first N rows")
    batch.add_argument(
        "--default-network",
        choices=["testnet", "mainnet"],
        default="mainnet",
        help="Fallback network when input row has no network",
    )
    batch.add_argument("--out", default="outputs/batch.jsonl", help="Output JSONL path")
    batch.add_argument("--summary", default="outputs/batch_summary.csv", help="Summary CSV path")
    batch.add_argument("--fail-fast", action="store_true", help="Stop on first failed row")
    batch.set_defaults(_handler=run_batch)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "_handler", None)
    if handler is None:
        parser.print_help()
        return 1
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
