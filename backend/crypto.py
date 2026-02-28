from __future__ import annotations

import hashlib


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = sha256(tag.encode("utf-8"))
    return sha256(tag_hash + tag_hash + data)


def compact_size(n: int) -> bytes:
    if n < 0:
        raise ValueError("compact_size requires non-negative integer")
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return bytes([253]) + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return bytes([254]) + n.to_bytes(4, "little")
    return bytes([255]) + n.to_bytes(8, "little")


def tap_leaf_hash(leaf_version: int, script: bytes) -> bytes:
    data = bytes([leaf_version]) + compact_size(len(script)) + script
    return tagged_hash("TapLeaf", data)


def tap_branch_hash(a: bytes, b: bytes) -> bytes:
    left, right = (a, b) if a <= b else (b, a)
    return tagged_hash("TapBranch", left + right)


def tap_tweak_hash(internal_key: bytes, merkle_root: bytes) -> bytes:
    return tagged_hash("TapTweak", internal_key + merkle_root)


def fmod(a: int, m: int) -> int:
    return ((a % m) + m) % m


def fpow(base: int, exp: int, m: int) -> int:
    return pow(fmod(base, m), exp, m)


def finv(a: int, m: int) -> int:
    return fpow(a, m - 2, m)


def point_add(
    p1: tuple[int, int] | None, p2: tuple[int, int] | None
) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if y1 != y2:
            return None
        lmbd = fmod(3 * x1 * x1 * finv(2 * y1, P), P)
        x3 = fmod(lmbd * lmbd - 2 * x1, P)
        y3 = fmod(lmbd * (x1 - x3) - y1, P)
        return (x3, y3)
    lmbd = fmod((y2 - y1) * finv(x2 - x1, P), P)
    x3 = fmod(lmbd * lmbd - x1 - x2, P)
    y3 = fmod(lmbd * (x1 - x3) - y1, P)
    return (x3, y3)


def point_mul(k: int) -> tuple[int, int] | None:
    result = None
    addend = (GX, GY)
    n = k
    while n > 0:
        if n & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        n >>= 1
    return result


def lift_x(x: int) -> tuple[int, int] | None:
    if x >= P:
        return None
    y2 = fmod(fpow(x, 3, P) + 7, P)
    y = fpow(y2, (P + 1) // 4, P)
    if fpow(y, 2, P) != y2:
        return None
    return (x, y) if (y % 2 == 0) else (x, P - y)


def _bech32_polymod(values: list[int]) -> int:
    chk = 1
    for value in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert_bits(data: bytes | list[int], from_bits: int, to_bits: int, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    out: list[int] = []
    maxv = (1 << to_bits) - 1
    for value in data:
        if value < 0 or (value >> from_bits):
            raise ValueError("Invalid value for convert_bits")
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        raise ValueError("Invalid padding in convert_bits")
    return out


def bech32m_encode(hrp: str, witness_version: int, witness_program: bytes) -> str:
    if witness_version < 0 or witness_version > 16:
        raise ValueError("Invalid witness version")
    words = [witness_version] + _convert_bits(witness_program, 8, 5, True)
    values = _bech32_hrp_expand(hrp) + words
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 0x2BC830A3
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    combined = words + checksum
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def bech32m_decode(addr: str) -> tuple[str, int, bytes]:
    if not (8 <= len(addr) <= 90):
        raise ValueError("Invalid bech32m address length")
    if addr.lower() != addr and addr.upper() != addr:
        raise ValueError("Mixed-case bech32m address")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        raise ValueError("Invalid bech32m separator position")
    hrp = addr[:pos]
    data_chars = addr[pos + 1 :]
    data: list[int] = []
    for c in data_chars:
        idx = CHARSET.find(c)
        if idx == -1:
            raise ValueError("Invalid bech32m character")
        data.append(idx)
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 0x2BC830A3:
        raise ValueError("Invalid bech32m checksum")
    if len(data) < 7:
        raise ValueError("Invalid bech32m data")
    witness_version = data[0]
    program = bytes(_convert_bits(data[1:-6], 5, 8, False))
    return hrp, witness_version, program
