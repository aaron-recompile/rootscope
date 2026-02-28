from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from .analyzer import AnalysisError, parse_control_block


ResolvedNetwork = Literal["testnet", "mainnet"]
FetchNetwork = Literal["auto", "testnet", "mainnet"]


@dataclass
class FetchWitnessError(Exception):
    code: str
    status_code: int
    message: str
    details: dict[str, Any] | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"ok": False, "errorCode": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        return payload


def _validate_txid(txid: str) -> str:
    compact = txid.strip().lower()
    if len(compact) != 64:
        raise FetchWitnessError("INVALID_TXID", 400, "txid must be 64 hex chars")
    try:
        int(compact, 16)
    except ValueError as exc:
        raise FetchWitnessError("INVALID_TXID", 400, "txid must be valid hex") from exc
    return compact


def _validate_vin(vin: int) -> int:
    if vin < 0:
        raise FetchWitnessError("INVALID_VIN", 400, "vin must be a non-negative integer")
    return vin


def _validate_network(network: str) -> FetchNetwork:
    if network not in {"auto", "testnet", "mainnet"}:
        raise FetchWitnessError("INVALID_NETWORK", 400, "network must be auto, testnet, or mainnet")
    return network  # type: ignore[return-value]


def _is_control_block_hex(item: str) -> bool:
    if not item or len(item) % 2 != 0:
        return False
    try:
        bytes.fromhex(item)
    except ValueError:
        return False
    if len(item) < 66:
        return False
    try:
        parse_control_block(item)
        return True
    except AnalysisError:
        return False


def _extract_from_tx_json(tx_json: dict[str, Any], vin: int) -> tuple[list[str], str, str, str | None]:
    vins = tx_json.get("vin")
    if not isinstance(vins, list):
        raise FetchWitnessError("WITNESS_MISSING", 422, "Transaction vin list missing")
    if vin >= len(vins):
        raise FetchWitnessError("VIN_OUT_OF_RANGE", 404, "vin out of range", {"vinCount": len(vins), "vin": vin})

    txin = vins[vin]
    prevout = txin.get("prevout") if isinstance(txin, dict) else None
    script_type = prevout.get("scriptpubkey_type") if isinstance(prevout, dict) else None
    if script_type and script_type != "v1_p2tr":
        raise FetchWitnessError("NOT_TAPROOT_INPUT", 422, "Input is not a Taproot input", {"scriptType": script_type})

    witness = txin.get("witness") if isinstance(txin, dict) else None
    if not isinstance(witness, list) or not witness:
        raise FetchWitnessError("WITNESS_MISSING", 422, "Input witness is missing")

    witness_stack = [str(x).strip().lower() for x in witness]
    cb_index = -1
    for i in range(len(witness_stack) - 1, -1, -1):
        if _is_control_block_hex(witness_stack[i]):
            cb_index = i
            break
    if cb_index == -1:
        raise FetchWitnessError("CONTROL_BLOCK_NOT_FOUND", 422, "No recognizable control block in witness")
    if cb_index == 0:
        raise FetchWitnessError("SCRIPT_NOT_FOUND", 422, "Could not infer script from witness")

    control_block = witness_stack[cb_index]
    script = witness_stack[cb_index - 1]
    if not script:
        raise FetchWitnessError("SCRIPT_NOT_FOUND", 422, "Extracted script is empty")

    expected_address = None
    if isinstance(prevout, dict):
        address = prevout.get("scriptpubkey_address")
        if isinstance(address, str) and address:
            expected_address = address.strip().lower()

    return witness_stack, script, control_block, expected_address


def _network_urls(txid: str, network: ResolvedNetwork) -> list[tuple[str, str]]:
    if network == "testnet":
        return [
            ("mempool", f"https://mempool.space/testnet/api/tx/{txid}"),
            ("blockstream", f"https://blockstream.info/testnet/api/tx/{txid}"),
        ]
    return [
        ("mempool", f"https://mempool.space/api/tx/{txid}"),
        ("blockstream", f"https://blockstream.info/api/tx/{txid}"),
    ]


def _fetch_json(url: str) -> dict[str, Any]:
    try:
        with urlopen(url, timeout=10) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except HTTPError as exc:
        if exc.code == 404:
            raise FetchWitnessError("TX_NOT_FOUND", 404, "Transaction not found on upstream") from exc
        raise FetchWitnessError("UPSTREAM_UNAVAILABLE", 503, f"Upstream HTTP error: {exc.code}") from exc
    except URLError as exc:
        raise FetchWitnessError("UPSTREAM_UNAVAILABLE", 503, "Could not reach upstream data source") from exc
    except json.JSONDecodeError as exc:
        raise FetchWitnessError("UPSTREAM_UNAVAILABLE", 503, "Upstream returned invalid JSON") from exc


def fetch_witness_by_txid(txid: str, vin: int, network: str = "auto") -> dict[str, Any]:
    txid = _validate_txid(txid)
    vin = _validate_vin(vin)
    network = _validate_network(network)

    candidate_networks: list[ResolvedNetwork]
    if network == "auto":
        candidate_networks = ["testnet", "mainnet"]
    else:
        candidate_networks = [network]  # type: ignore[list-item]

    not_found_count = 0
    upstream_errors: list[str] = []

    for resolved_network in candidate_networks:
        for source, url in _network_urls(txid, resolved_network):
            try:
                tx_json = _fetch_json(url)
                witness_stack, script_hex, control_block_hex, expected_address = _extract_from_tx_json(tx_json, vin)
                return {
                    "ok": True,
                    "source": source,
                    "network": resolved_network,
                    "txid": txid,
                    "vin": vin,
                    "scriptHex": script_hex,
                    "controlBlockHex": control_block_hex,
                    "expectedAddress": expected_address,
                    "witnessStack": witness_stack,
                    "notes": ["detected script-path witness format"],
                }
            except FetchWitnessError as exc:
                if exc.code == "TX_NOT_FOUND":
                    not_found_count += 1
                    continue
                if exc.code == "UPSTREAM_UNAVAILABLE":
                    upstream_errors.append(f"{source}:{resolved_network}")
                    continue
                raise

    if not_found_count > 0 and not_found_count == len(candidate_networks) * 2:
        raise FetchWitnessError("TX_NOT_FOUND", 404, "Transaction not found")
    if upstream_errors:
        raise FetchWitnessError(
            "UPSTREAM_UNAVAILABLE",
            503,
            "All upstream providers failed",
            {"attempts": upstream_errors},
        )
    raise FetchWitnessError("INTERNAL_ERROR", 500, "Unexpected fetch flow failure")
