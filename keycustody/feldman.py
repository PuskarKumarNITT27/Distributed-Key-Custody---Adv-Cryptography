"""Shamir secret sharing over Z_n (n = secp256k1 order) with Feldman verifiable commitments."""
import secrets
from . import secp
from .secp import N

def _eval(coeffs, x):
    r = 0
    for c in reversed(coeffs): r = (r * x + c) % N
    return r

def split(secret: int, t: int, n: int):
    """Return (shares [(x,y)], commitments [C_0..C_{t-1}]) with C_j = a_j*G."""
    if not isinstance(secret, int) or not (1 <= secret < N):
        raise ValueError("secret must be an integer in [1, secp256k1_order - 1]")
    if not isinstance(t, int) or not isinstance(n, int) or not (2 <= t <= n):
        raise ValueError("need integers satisfying 2 <= t <= n")
    if n >= N:
        raise ValueError("number of shares must be smaller than the curve order")
    coeffs = [secret] + [secrets.randbelow(N) for _ in range(t - 1)]
    return [(x, _eval(coeffs, x)) for x in range(1, n + 1)], [secp.mul(c) for c in coeffs]

def verify(x: int, y: int, commits) -> bool:
    if not isinstance(x, int) or not (1 <= x < N): return False
    if not isinstance(y, int) or not (0 <= y < N): return False
    if not commits: return False
    rhs, xp = None, 1
    for C in commits:
        rhs = secp.add(rhs, secp.mul(xp, C)); xp = xp * x % N
    return secp.mul(y) == rhs

def combine(shares) -> int:
    if not shares: raise ValueError("at least one share is required")
    xs = [x for x, _ in shares]
    if any(not isinstance(x, int) or not (1 <= x < N) for x in xs):
        raise ValueError("share indices must be in [1, curve order - 1]")
    if any(not isinstance(y, int) or not (0 <= y < N) for _, y in shares):
        raise ValueError("share values must be in [0, curve order - 1]")
    if len(set(xs)) != len(xs): raise ValueError("duplicate shares")
    s = 0
    for i, (xi, yi) in enumerate(shares):
        num = den = 1
        for j, (xj, _) in enumerate(shares):
            if i != j: num = num * (-xj) % N; den = den * (xi - xj) % N
        s = (s + yi * num * pow(den, -1, N)) % N
    return s

def zero_delta(t: int, xs):
    """Proactive refresh: random polynomial with f(0)=0. Returns ({x: delta}, commitments with D_0=None)."""
    coeffs = [0] + [secrets.randbelow(N - 1) + 1 for _ in range(t - 1)]
    return {x: _eval(coeffs, x) for x in xs}, [None] + [secp.mul(c) for c in coeffs[1:]]

def add_commits(a, b):
    return [secp.add(p, q) for p, q in zip(a, b)]
