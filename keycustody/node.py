"""Validator node: holds ECIES-encrypted key shares, authenticates owners, gossips peers."""
import asyncio, hashlib, json, os, random, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from . import ecies, feldman, secp
from .net import send, recv, rpc, canon
from .secp import N

def share_aad(kid, x, ver): return f"{kid}|{x}|{ver}|share".encode()
def delta_aad(kid, x, ver): return f"{kid}|{x}|{ver}|delta".encode()

class Node:
    def __init__(self, data_dir=None, host="127.0.0.1", port=0, bootstrap=None, gossip_interval=2.0):
        self.host, self.port, self.data_dir = host, port, data_dir
        self.bootstrap = [tuple(b) for b in (bootstrap or [])]
        self.gossip_interval = gossip_interval
        if data_dir: os.makedirs(data_dir, exist_ok=True)
        self.sk = self._load_key()
        self.pub = self.sk.public_key().public_bytes_raw()
        self.id = hashlib.sha256(self.pub).hexdigest()[:16]
        self.store, self.peers, self.seen = {}, {}, {}
        self.byzantine = False          # test hook: serve corrupted shares
        self._load_store()
        self._server = self._task = None

    # ---------- persistence ----------
    def _load_key(self):
        if self.data_dir:
            p = os.path.join(self.data_dir, "node_key.hex")
            if os.path.exists(p):
                return X25519PrivateKey.from_private_bytes(bytes.fromhex(open(p).read().strip()))
            sk = X25519PrivateKey.generate()
            fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, "w") as f: f.write(sk.private_bytes_raw().hex())
            return sk
        return X25519PrivateKey.generate()

    def _load_store(self):
        if self.data_dir and os.path.exists(os.path.join(self.data_dir, "store.json")):
            self.store = json.load(open(os.path.join(self.data_dir, "store.json")))

    def _save(self):
        if self.data_dir:
            path = os.path.join(self.data_dir, "store.json")
            temp = path + ".tmp"
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump(self.store, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)

    # ---------- lifecycle ----------
    def info(self): return {"id": self.id, "addr": [self.host, self.port], "pub": self.pub.hex()}

    async def start(self):
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        for b in self.bootstrap: await self._hello(b)
        self._task = asyncio.create_task(self._gossip())
        return self

    async def stop(self):
        if self._task: self._task.cancel()
        if self._server: self._server.close(); await self._server.wait_closed()

    # ---------- gossip / peer discovery ----------
    def _add_peer(self, p):
        if p["id"] != self.id and p["id"] not in self.peers:
            if hashlib.sha256(bytes.fromhex(p["pub"])).hexdigest()[:16] == p["id"]:
                self.peers[p["id"]] = {**p, "fails": 0}

    async def _hello(self, addr):
        try:
            r = await rpc(addr, {"op": "hello", **self.info()}, timeout=2)
            self._add_peer(r["self"])
            for p in r["peers"]: self._add_peer(p)
            if r["self"]["id"] in self.peers: self.peers[r["self"]["id"]]["fails"] = 0
            return True
        except Exception:
            return False

    async def _gossip(self):
        while True:
            await asyncio.sleep(self.gossip_interval)
            cands = [(p["id"], tuple(p["addr"])) for p in self.peers.values()]
            for pid, addr in random.sample(cands, min(3, len(cands))):
                if not await self._hello(addr) and pid in self.peers:
                    self.peers[pid]["fails"] += 1
                    if self.peers[pid]["fails"] >= 3: del self.peers[pid]
            if not self.peers:
                for b in self.bootstrap: await self._hello(b)

    # ---------- request handling ----------
    async def _handle(self, reader, writer):
        try:
            req = await recv(reader)
            try:
                resp = await getattr(self, "op_" + str(req.get("op")))(req)
            except Exception as e:
                resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            await send(writer, resp)
        except Exception:
            pass
        finally:
            writer.close()

    def _auth(self, b):
        b = dict(b); sig = bytes.fromhex(b.pop("sig"))
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(b["owner"])).verify(sig, canon(b))
        if b["node"] != self.id: raise PermissionError("request addressed to another node")
        now = time.time()
        if abs(now - b["ts"]) > 60: raise PermissionError("stale timestamp")
        self.seen = {k: v for k, v in self.seen.items() if v > now}
        if b["nonce"] in self.seen: raise PermissionError("replayed request")
        self.seen[b["nonce"]] = now + 120
        rec = self.store.get(b["key_id"])
        if rec and rec["owner"] != b["owner"]: raise PermissionError("not the key owner")

    async def op_hello(self, b):
        if b.get("addr"): self._add_peer({"id": b["id"], "addr": b["addr"], "pub": b["pub"]})
        return {"ok": True, "self": self.info(), "peers": [{k: p[k] for k in ("id", "addr", "pub")} for p in self.peers.values()]}

    def _prune(self, rec):
        for v in sorted(map(int, rec["versions"]))[:-2]: del rec["versions"][str(v)]

    async def op_put(self, b):
        self._auth(b)
        kid, ver, x = b["key_id"], int(b["version"]), int(b["x"])
        if not isinstance(kid, str) or not kid or len(kid) > 256: raise ValueError("invalid key_id")
        if ver < 1 or not (1 <= x < N): raise ValueError("invalid version or share index")
        if not isinstance(b["commitments"], list) or not b["commitments"]: raise ValueError("missing commitments")
        commits = [secp.decode(c) for c in b["commitments"]]
        y = int.from_bytes(ecies.open_(self.sk, bytes.fromhex(b["envelope"]), share_aad(kid, x, ver)), "big")
        if not feldman.verify(x, y, commits): raise ValueError("share fails Feldman verification")
        rec = self.store.setdefault(kid, {"owner": b["owner"], "versions": {}})
        if str(ver) in rec["versions"]: raise ValueError("version exists")
        rec["versions"][str(ver)] = {"x": x, "commitments": b["commitments"], "envelope": b["envelope"]}
        self._prune(rec); self._save()
        return {"ok": True}

    async def op_get(self, b):
        self._auth(b)
        kid, ver = b["key_id"], int(b["version"])
        v = self.store.get(kid, {}).get("versions", {}).get(str(ver))
        if not v: raise KeyError("no such share/version")
        y = int.from_bytes(ecies.open_(self.sk, bytes.fromhex(v["envelope"]), share_aad(kid, v["x"], ver)), "big")
        if self.byzantine: y = (y + 1) % N
        env = ecies.seal(bytes.fromhex(b["reply_pub"]), y.to_bytes(32, "big"), share_aad(kid, v["x"], ver))
        return {"ok": True, "x": v["x"], "version": ver, "share": env.hex()}

    async def op_refresh(self, b):
        """Proactive refresh: y' = y + delta (delta from a zero-constant polynomial); secret unchanged."""
        self._auth(b)
        kid, base = b["key_id"], int(b["base_version"]); nv = base + 1
        rec = self.store.get(kid)
        v = rec and rec["versions"].get(str(base))
        if not v: raise KeyError("base version not held")
        x = v["x"]
        y = int.from_bytes(ecies.open_(self.sk, bytes.fromhex(v["envelope"]), share_aad(kid, x, base)), "big")
        d = int.from_bytes(ecies.open_(self.sk, bytes.fromhex(b["delta_env"]), delta_aad(kid, x, nv)), "big")
        dc = [secp.decode(c) for c in b["delta_commits"]]
        if dc[0] is not None or not feldman.verify(x, d, dc): raise ValueError("bad delta")
        newc = feldman.add_commits([secp.decode(c) for c in v["commitments"]], dc)
        y2 = (y + d) % N
        if not feldman.verify(x, y2, newc): raise ValueError("refreshed share fails verification")
        rec["versions"][str(nv)] = {"x": x, "commitments": [secp.encode(c) for c in newc],
                                    "envelope": ecies.seal(self.pub, y2.to_bytes(32, "big"), share_aad(kid, x, nv)).hex()}
        self._prune(rec); self._save()
        return {"ok": True}

    async def op_finalize_refresh(self, b):
        """Erase older locally stored versions after the client confirms refresh completion."""
        self._auth(b)
        kid, ver = b["key_id"], int(b["version"])
        rec = self.store.get(kid)
        if not rec or str(ver) not in rec["versions"]:
            raise KeyError("refreshed version not held")
        rec["versions"] = {str(ver): rec["versions"][str(ver)]}
        self._save()
        return {"ok": True}
