"""Minimal secp256k1 arithmetic (pure Python, educational; not constant-time)."""
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def add(a, b):
    if a is None: return b
    if b is None: return a
    x1, y1 = a; x2, y2 = b
    if x1 == x2:
        if (y1 + y2) % P == 0: return None
        lam = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)

def mul(k, pt=G):
    k %= N; r = None; q = pt
    while k:
        if k & 1: r = add(r, q)
        q = add(q, q); k >>= 1
    return r

def encode(pt) -> str:
    if pt is None: return "00" * 33
    return (b"\x02" if pt[1] % 2 == 0 else b"\x03").hex() + pt[0].to_bytes(32, "big").hex()

def decode(h: str):
    raw = bytes.fromhex(h)
    if raw == b"\x00" * 33: return None
    x = int.from_bytes(raw[1:], "big")
    y = pow((x**3 + 7) % P, (P + 1) // 4, P)
    if (y % 2) != (raw[0] - 2): y = P - y
    if (y * y - x**3 - 7) % P: raise ValueError("point not on curve")
    return (x, y)
