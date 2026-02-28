from __future__ import annotations

from dataclasses import dataclass

from .crypto import (
    N,
    bech32m_decode,
    bech32m_encode,
    lift_x,
    point_add,
    point_mul,
    tap_branch_hash,
    tap_leaf_hash,
    tap_tweak_hash,
)
from .models import AnalysisChecks, AnalyzeResponse, ControlBlockInfo, StepInfo


@dataclass
class AnalysisError(Exception):
    code: str
    message: str

    def __str__(self) -> str:
        return self.message


def _sanitize_hex(value: str, label: str) -> str:
    compact = "".join(value.split()).lower()
    if not compact:
        raise AnalysisError("EMPTY_INPUT", f"{label} is required")
    if len(compact) % 2 != 0:
        raise AnalysisError("INVALID_HEX", f"{label} must contain an even number of hex characters")
    try:
        int(compact, 16)
    except ValueError as exc:
        raise AnalysisError("INVALID_HEX", f"{label} contains non-hex characters") from exc
    return compact


def parse_control_block(control_block_hex: str) -> tuple[ControlBlockInfo, list[bytes], bytes]:
    cb_hex = _sanitize_hex(control_block_hex, "controlBlock")
    cb_bytes = bytes.fromhex(cb_hex)

    if len(cb_bytes) < 33:
        raise AnalysisError("CONTROL_BLOCK_TOO_SHORT", f"Control block too short: {len(cb_bytes)} bytes")
    if (len(cb_bytes) - 33) % 32 != 0:
        raise AnalysisError("CONTROL_BLOCK_LENGTH_INVALID", f"Invalid control block length: {len(cb_bytes)} bytes")

    depth = (len(cb_bytes) - 33) // 32
    if depth > 128:
        raise AnalysisError("CONTROL_BLOCK_DEPTH_INVALID", f"Control block depth too large: {depth}")

    version_byte = cb_bytes[0]
    siblings: list[bytes] = []
    path_hex: list[str] = []
    for i in range(depth):
        sibling = cb_bytes[33 + i * 32 : 33 + (i + 1) * 32]
        siblings.append(sibling)
        path_hex.append(sibling.hex())

    cb = ControlBlockInfo(
        raw=cb_hex,
        versionByte=version_byte,
        leafVersion=version_byte & 0xFE,
        parity=version_byte & 0x01,
        internalKey=cb_bytes[1:33].hex(),
        depth=depth,
        path=path_hex,
    )
    return cb, siblings, cb_bytes[1:33]


def analyze_taproot(
    *,
    control_block: str,
    script: str,
    network: str,
    expected_address: str | None = None,
) -> AnalyzeResponse:
    if network not in {"testnet", "mainnet"}:
        raise AnalysisError("NETWORK_INVALID", "network must be testnet or mainnet")

    cb, siblings, internal_key_bytes = parse_control_block(control_block)
    script_hex = _sanitize_hex(script, "script")
    script_bytes = bytes.fromhex(script_hex)

    steps: list[StepInfo] = []
    leaf = tap_leaf_hash(cb.leafVersion, script_bytes)
    steps.append(
        StepInfo(
            id="leaf",
            label="TapLeaf Hash",
            formula=f'TaggedHash("TapLeaf", 0x{cb.leafVersion:02x} || compact_size({len(script_bytes)}) || script)',
            hash=leaf.hex(),
            type="leaf",
        )
    )

    current = leaf
    for i, sibling in enumerate(siblings):
        is_left = current <= sibling
        left = current if is_left else sibling
        right = sibling if is_left else current
        current = tap_branch_hash(current, sibling)
        steps.append(
            StepInfo(
                id=f"branch_{i}",
                label="Merkle Root" if i == len(siblings) - 1 else f"TapBranch (depth {cb.depth - i - 1})",
                formula=f'TaggedHash("TapBranch", {"current" if is_left else "sibling"} || {"sibling" if is_left else "current"})',
                hash=current.hex(),
                leftHash=left.hex(),
                rightHash=right.hex(),
                sibling=sibling.hex(),
                siblingIsRight=is_left,
                type="root" if i == len(siblings) - 1 else "branch",
            )
        )

    merkle_root = current
    tweak = tap_tweak_hash(internal_key_bytes, merkle_root)
    tweak_int = int.from_bytes(tweak, "big")
    if tweak_int >= N:
        raise AnalysisError("TWEAK_OUT_OF_RANGE", "Tweak is greater than or equal to curve order")

    internal_x = int.from_bytes(internal_key_bytes, "big")
    p = lift_x(internal_x)
    if p is None:
        raise AnalysisError("INVALID_INTERNAL_KEY", "Cannot lift internal key x-coordinate")

    tweak_point = point_mul(tweak_int)
    q = point_add(p, tweak_point)
    if q is None:
        raise AnalysisError("POINT_AT_INFINITY", "Tweaked point is point at infinity")

    out_x, out_y = q
    output_key = out_x.to_bytes(32, "big")
    computed_parity = out_y & 1
    parity_match = computed_parity == cb.parity

    hrp = "tb" if network == "testnet" else "bc"
    address = bech32m_encode(hrp, 1, output_key)

    checks = AnalysisChecks(
        expectedProvided=bool(expected_address),
        expectedAddressMatch=None,
        expectedAddressReason=None,
        parityMatch=parity_match,
    )

    if expected_address:
        expected = expected_address.strip()
        try:
            exp_hrp, exp_ver, exp_prog = bech32m_decode(expected)
            if exp_ver != 1 or len(exp_prog) != 32:
                checks.expectedAddressReason = "Expected address is not a v1 32-byte Taproot address"
                checks.expectedAddressMatch = False
            elif exp_hrp != hrp:
                checks.expectedAddressReason = f"Expected address HRP {exp_hrp} does not match selected network {hrp}"
                checks.expectedAddressMatch = False
            else:
                checks.expectedAddressMatch = exp_prog.hex() == output_key.hex()
                if not checks.expectedAddressMatch:
                    checks.expectedAddressReason = "Expected address witness program differs from reconstructed output key"
        except ValueError as exc:
            raise AnalysisError("EXPECTED_ADDRESS_INVALID", str(exc)) from exc

    return AnalyzeResponse(
        cb=cb,
        steps=steps,
        leafHex=leaf.hex(),
        merkleRootHex=merkle_root.hex(),
        tweakHex=tweak.hex(),
        outputKey=output_key.hex(),
        computedParity=computed_parity,
        parityMatch=parity_match,
        address=address,
        checks=checks,
    )
