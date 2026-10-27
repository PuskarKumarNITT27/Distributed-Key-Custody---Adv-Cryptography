import asyncio, json
MAX = 4 * 1024 * 1024

async def send(w, obj):
    data = json.dumps(obj).encode()
    w.write(len(data).to_bytes(4, "big") + data); await w.drain()

async def recv(r):
    n = int.from_bytes(await r.readexactly(4), "big")
    if n == 0 or n > MAX: raise ValueError("invalid message length")
    obj = json.loads(await r.readexactly(n))
    if not isinstance(obj, dict): raise ValueError("message must be a JSON object")
    return obj

async def rpc(addr, obj, timeout=5.0):
    async def go():
        r, w = await asyncio.open_connection(addr[0], int(addr[1]))
        try:
            await send(w, obj); return await recv(r)
        finally:
            w.close()
            try: await w.wait_closed()
            except (ConnectionError, asyncio.CancelledError): pass
    return await asyncio.wait_for(go(), timeout)

def canon(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
