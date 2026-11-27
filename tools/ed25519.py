# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""Pure-Python Ed25519 (RFC 8032 reference formulas) — GRAFT Phase 2.
The tool stays stdlib-only: no third-party crypto dependency enters the store's
toolchain. Correctness is pinned by (a) the RFC 8032 TEST 1 key-derivation vector in
tests/test_phase2.py and (b) an OpenSSL cross-verification logged during development.
Signing/verifying a handful of captures takes milliseconds; this is not a hot path."""
import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _inv(x):
    return pow(x, P - 2, P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * SQRT_M1) % P
    if (x * x - xx) % P != 0:
        raise ValueError("point not on curve")
    # canonical representative: the even root (RFC 8032's base point is even-x;
    # decodepoint flips to the odd root only when the sign bit says so)
    if x % 2 != 0:
        x = P - x
    return x


_BY = (4 * _inv(5)) % P
_BX = _xrecover(_BY)
B = (_BX % P, _BY, 1, (_BX * _BY) % P)  # extended coordinates (X, Y, Z, T)


def _edwards_add(Pn, Q):
    x1, y1, z1, t1 = Pn
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    dd = z1 * 2 * z2 % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(Pn, e):
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(Pn, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, Pn)
    return Q


def _encodepoint(Pn):
    x, y, z, _ = Pn
    zi = _inv(z)
    x = x * zi % P
    y = y * zi % P
    return int(y | ((x & 1) << 255)).to_bytes(32, "little")


def _encodeint(i):
    return i.to_bytes(32, "little")


def _hint(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _secret_expand(seed):
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a, h[32:]


def publickey(seed):
    a, _ = _secret_expand(seed)
    return _encodepoint(_scalarmult(B, a))


def signature(seed, msg):
    a, prefix = _secret_expand(seed)
    A = _encodepoint(_scalarmult(B, a))
    r = _hint(prefix + msg) % L
    R = _scalarmult(B, r)
    Rs = _encodepoint(R)
    h = _hint(Rs + A + msg) % L
    s = (r + h * a) % L
    return Rs + _encodeint(s)


def _decodepoint(s):
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None
    try:
        x = _xrecover(y)
    except ValueError:
        return None  # non-square y: not a curve point — verification must fail cleanly
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, (x * y) % P)


def _pequal(Pn, Q):
    x1, y1, z1, _ = Pn
    x2, y2, z2, _ = Q
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def checkvalid(sig, msg, pub):
    """Strict RFC 8032 verification: length, S < L, curve membership, R = SB - HA.
    Returns (ok, reason)."""
    if len(sig) != 64 or len(pub) != 32:
        return False, "bad length"
    R = _decodepoint(sig[:32])
    A = _decodepoint(pub)
    if R is None or A is None:
        return False, "point not on curve"
    S = int.from_bytes(sig[32:], "little")
    if S >= L:
        return False, "S out of range"
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little")
    left = _scalarmult(B, S)
    right = _edwards_add(R, _scalarmult(A, h))
    if not _pequal(left, right):
        return False, "signature mismatch"
    return True, ""
