import asyncio, secrets, unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from keycustody import feldman, secp, ecies
from keycustody.client import CustodyClient, CustodyError
from keycustody.localnet import LocalNetwork
from keycustody.net import rpc
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

class Crypto(unittest.TestCase):
    def test_curve(self):
        self.assertEqual(secp.mul(secp.N), None)
        self.assertEqual(secp.decode(secp.encode(secp.mul(12345))), secp.mul(12345))
    def test_split_combine_any_subset(self):
        s = secrets.randbelow(secp.N); sh, c = feldman.split(s, 3, 6)
        self.assertTrue(all(feldman.verify(x, y, c) for x, y in sh))
        self.assertEqual(feldman.combine([sh[5], sh[0], sh[3]]), s)
        self.assertNotEqual(feldman.combine(sh[:2]), s)
    def test_tamper_detected(self):
        sh, c = feldman.split(7, 3, 5); x, y = sh[0]
        self.assertFalse(feldman.verify(x, y + 1, c))

    def test_rejects_invalid_secret_and_threshold(self):
        for secret in (0, -1, secp.N):
            with self.assertRaises(ValueError): feldman.split(secret, 2, 3)
        for t, n in ((1, 3), (4, 3), (2, 1)):
            with self.assertRaises(ValueError): feldman.split(7, t, n)

    def test_combine_rejects_duplicate_or_empty_shares(self):
        with self.assertRaises(ValueError): feldman.combine([])
        with self.assertRaises(ValueError): feldman.combine([(1, 2), (1, 3)])
    def test_ecies(self):
        k = X25519PrivateKey.generate(); b = ecies.seal(k.public_key().public_bytes_raw(), b"hi", b"a")
        self.assertEqual(ecies.open_(k, b, b"a"), b"hi")
        with self.assertRaises(Exception): ecies.open_(k, b, b"other-aad")

class Network(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.net = await LocalNetwork(7).__aenter__()
        self.c = CustodyClient(); self.nodes = await self.c.discover(self.net.bootstrap)
        self.secret = secrets.randbelow(secp.N - 1) + 1
        self.m = await self.c.store("k1", self.secret, 4, 7, self.nodes)
    async def asyncTearDown(self): await self.net.__aexit__()

    async def test_gossip_discovery(self): self.assertEqual(len(self.nodes), 7)
    async def test_recover(self): self.assertEqual(await self.c.recover(self.m), self.secret)
    async def test_tolerates_n_minus_t_failures(self):
        for nd in self.net.nodes[4:]: await nd.stop()   # 3 down, node0 (bootstrap) stays
        self.assertEqual(await self.c.recover(self.m, timeout=1), self.secret)
    async def test_fails_below_threshold(self):
        for nd in self.net.nodes[3:]: await nd.stop()   # 4 down -> 3 left < t
        with self.assertRaises(CustodyError): await self.c.recover(self.m, timeout=1)
    async def test_byzantine_share_rejected(self):
        for nd in self.net.nodes[:3]: nd.byzantine = True
        self.assertEqual(await self.c.recover(self.m), self.secret)
    async def test_non_owner_denied(self):
        with self.assertRaises(CustodyError): await CustodyClient().recover(self.m)
    async def test_replay_denied(self):
        nd = self.m["nodes"][0]
        req = self.c._signed(nd["id"], {"op": "get", "key_id": "k1", "version": 1,
                                        "reply_pub": X25519PrivateKey.generate().public_key().public_bytes_raw().hex()})
        self.assertTrue((await rpc(nd["addr"], req))["ok"])
        self.assertIn("replayed", (await rpc(nd["addr"], req))["error"])
    async def test_refresh(self):
        old = await self._shares(self.m)
        m2 = await self.c.refresh(self.m)
        self.assertEqual(m2["pubkey"], self.m["pubkey"]); self.assertEqual(m2["version"], 2)
        self.assertEqual(await self.c.recover(m2), self.secret)
        new = await self._shares(m2)
        self.assertTrue(all(old[x] != new[x] for x in old))
        mixed = [(x, old[x]) for x in (1, 2)] + [(x, new[x]) for x in (3, 4)]
        self.assertNotEqual(feldman.combine(mixed), self.secret)       # stolen old shares useless
        with self.assertRaises(CustodyError):
            await self.c.recover(self.m)  # old version is removed after successful refresh
    async def _shares(self, m):
        from keycustody.node import share_aad
        out = {}
        for nd in self.net.nodes:
            v = nd.store["k1"]["versions"].get(str(m["version"]))
            out[v["x"]] = int.from_bytes(ecies.open_(nd.sk, bytes.fromhex(v["envelope"]), share_aad("k1", v["x"], m["version"])), "big")
        return out
    async def test_bad_share_rejected_at_store(self):
        nodes = self.nodes; sh, c = feldman.split(5, 2, 2)
        # a distribution with an inconsistent share must be refused by the node (Feldman check)
        nd = nodes[0]; x, y = sh[0]
        env = ecies.seal(bytes.fromhex(nd["pub"]), ((y + 1) % secp.N).to_bytes(32, "big"), f"bad|{x}|1|share".encode())
        r = await rpc(nd["addr"], self.c._signed(nd["id"], {"op": "put", "key_id": "bad", "version": 1, "x": x,
              "commitments": [secp.encode(p) for p in c], "envelope": env.hex()}))
        self.assertFalse(r["ok"])

if __name__ == "__main__": unittest.main()
