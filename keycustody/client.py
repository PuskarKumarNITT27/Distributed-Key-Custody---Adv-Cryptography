"""User-side client: split, distribute, recover, refresh."""
import asyncio, random, secrets, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from . import ecies, feldman, secp
from .net import rpc, canon
from .node import share_aad, delta_aad
from .secp import N

class CustodyError(Exception): pass

class CustodyClient:
    def __init__(self, identity: Ed25519PrivateKey = None):
        self.sk = identity or Ed25519PrivateKey.generate()
        self.owner = self.sk.public_key().public_bytes_raw().hex()

    def _signed(self, node_id, body):
        body = {**body, "owner": self.owner, "node": node_id, "ts": time.time(), "nonce": secrets.token_hex(12)}
        body["sig"] = self.sk.sign(canon(body)).hex()
        return body

    async def discover(self, bootstrap):
        r = await rpc(bootstrap, {"op": "hello"})
        return [r["self"]] + r["peers"]

    async def store(self, key_id, secret: int, t, n, nodes):
        if len(nodes) < n: raise CustodyError(f"need {n} nodes, have {len(nodes)}")
        chosen = random.sample(nodes, n)
        shares, commits = feldman.split(secret, t, n)
        enc = [secp.encode(c) for c in commits]
        async def put(node, x, y):
            env = ecies.seal(bytes.fromhex(node["pub"]), y.to_bytes(32, "big"), share_aad(key_id, x, 1))
            return await rpc(node["addr"], self._signed(node["id"], {
                "op": "put", "key_id": key_id, "version": 1, "x": x, "commitments": enc, "envelope": env.hex()}))
        res = await asyncio.gather(*[put(nd, x, y) for nd, (x, y) in zip(chosen, shares)], return_exceptions=True)
        bad = [r for r in res if isinstance(r, Exception) or not r.get("ok")]
        if bad: raise CustodyError(f"{len(bad)}/{n} nodes rejected/failed the store: {bad[0]}")
        return {"key_id": key_id, "owner": self.owner, "t": t, "n": n, "version": 1,
                "pubkey": enc[0], "commitments": enc,
                "nodes": [{**nd, "x": x} for nd, (x, _) in zip(chosen, shares)]}

    async def recover(self, m, timeout=5.0):
        commits = [secp.decode(c) for c in m["commitments"]]
        eph = X25519PrivateKey.generate(); eph_pub = eph.public_key().public_bytes_raw().hex()
        async def get(nd):
            r = await rpc(nd["addr"], self._signed(nd["id"], {"op": "get", "key_id": m["key_id"],
                          "version": m["version"], "reply_pub": eph_pub}), timeout)
            if not r.get("ok"): raise CustodyError(r.get("error"))
            y = int.from_bytes(ecies.open_(eph, bytes.fromhex(r["share"]), share_aad(m["key_id"], nd["x"], m["version"])), "big")
            if r["x"] != nd["x"] or not feldman.verify(nd["x"], y, commits):
                raise CustodyError(f"node {nd['id']} returned an invalid share")
            return (nd["x"], y)
        pending = {asyncio.create_task(get(nd)) for nd in m["nodes"]}
        good, rejected = [], []
        while pending and len(good) < m["t"]:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for d in done:
                (rejected if d.exception() else good).append(d.exception() or d.result())
        for p in pending: p.cancel()
        if len(good) < m["t"]:
            raise CustodyError(f"only {len(good)}/{m['t']} valid shares; failures: {[str(r) for r in rejected][:3]}")
        s = feldman.combine(good[:m["t"]])
        if secp.encode(secp.mul(s)) != m["pubkey"]: raise CustodyError("reconstructed key mismatch")
        return s

    async def refresh(self, m):
        """Re-randomise all shares without reconstructing the key. Manifest only advances if ALL nodes succeed."""
        nv = m["version"] + 1
        deltas, dcommits = feldman.zero_delta(m["t"], [nd["x"] for nd in m["nodes"]])
        dc = [secp.encode(c) for c in dcommits]
        async def ref(nd):
            env = ecies.seal(bytes.fromhex(nd["pub"]), deltas[nd["x"]].to_bytes(32, "big"), delta_aad(m["key_id"], nd["x"], nv))
            return await rpc(nd["addr"], self._signed(nd["id"], {"op": "refresh", "key_id": m["key_id"],
                             "base_version": m["version"], "delta_env": env.hex(), "delta_commits": dc}))
        res = await asyncio.gather(*[ref(nd) for nd in m["nodes"]], return_exceptions=True)
        bad = [r for r in res if isinstance(r, Exception) or not r.get("ok")]
        if bad: raise CustodyError(f"refresh incomplete ({len(bad)} failures); old version still valid: {bad[0]}")
        # Only prune old local versions after every node has acknowledged the new share.
        async def finalize(nd):
            return await rpc(nd["addr"], self._signed(nd["id"], {
                "op": "finalize_refresh", "key_id": m["key_id"], "version": nv
            }))
        cleanup = await asyncio.gather(*[finalize(nd) for nd in m["nodes"]], return_exceptions=True)
        failed_cleanup = [r for r in cleanup if isinstance(r, Exception) or not r.get("ok")]
        newc = feldman.add_commits([secp.decode(c) for c in m["commitments"]], dcommits)
        result = {**m, "version": nv, "commitments": [secp.encode(c) for c in newc]}
        if failed_cleanup:
            # Preserve the new manifest so the caller can still recover. Some nodes may
            # retain an older local copy; report this rather than losing the new version.
            result["cleanup_warnings"] = [
                f"old-version cleanup failed on {len(failed_cleanup)} node(s)"
            ]
        else:
            result.pop("cleanup_warnings", None)
        return result
