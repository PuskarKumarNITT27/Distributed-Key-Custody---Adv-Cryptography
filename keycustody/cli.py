"""CLI:
  python -m keycustody.cli node --port 9001 --data ./n1 [--bootstrap 127.0.0.1:9001]
  python -m keycustody.cli store --bootstrap 127.0.0.1:9001 -t 3 -n 5 [--key-hex HEX] --manifest m.json
  python -m keycustody.cli recover --manifest m.json
  python -m keycustody.cli refresh --manifest m.json
"""
import argparse, asyncio, json, os, secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .client import CustodyClient
from .node import Node
from . import secp

def addr(s): h, p = s.rsplit(":", 1); return (h, int(p))

def identity(path):
    if os.path.exists(path): return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(path).read().strip()))
    sk = Ed25519PrivateKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, "w") as f: f.write(sk.private_bytes_raw().hex())
    return sk

async def main():
    ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("node"); n.add_argument("--host", default="127.0.0.1"); n.add_argument("--port", type=int, default=0)
    n.add_argument("--data"); n.add_argument("--bootstrap", action="append", default=[])
    for name in ("store", "recover", "refresh"):
        p = sub.add_parser(name); p.add_argument("--manifest", required=True); p.add_argument("--identity", default="owner.key")
        if name == "store":
            p.add_argument("--bootstrap", required=True, type=addr); p.add_argument("-t", type=int, required=True)
            p.add_argument("-n", type=int, required=True); p.add_argument("--key-hex"); p.add_argument("--key-id", default="default")
    a = ap.parse_args()
    if a.cmd == "node":
        nd = await Node(data_dir=a.data, host=a.host, port=a.port, bootstrap=[addr(b) for b in a.bootstrap]).start()
        print(f"node {nd.id} listening on {nd.host}:{nd.port}"); await asyncio.Event().wait()
    c = CustodyClient(identity(a.identity))
    if a.cmd == "store":
        s = int(a.key_hex, 16) if a.key_hex else secrets.randbelow(secp.N - 1) + 1
        m = await c.store(a.key_id, s, a.t, a.n, await c.discover(a.bootstrap))
        json.dump(m, open(a.manifest, "w"), indent=2)
        print("stored; public key:", m["pubkey"], "| manifest ->", a.manifest)
    else:
        m = json.load(open(a.manifest))
        if a.cmd == "recover": print("recovered private key:", hex(await c.recover(m)))
        else:
            updated = await c.refresh(m)
            with open(a.manifest, "w", encoding="utf-8") as handle:
                json.dump(updated, handle, indent=2)
            print("refreshed ->", a.manifest)
            for warning in updated.get("cleanup_warnings", []):
                print("WARNING:", warning)

if __name__ == "__main__": asyncio.run(main())
