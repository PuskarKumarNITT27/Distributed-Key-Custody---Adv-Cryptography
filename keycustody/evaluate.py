"""Evaluation artifacts: python -m keycustody.evaluate  -> results.json + results.md"""
import asyncio, json, secrets, statistics as st, time
from . import feldman, secp
from .client import CustodyClient, CustodyError
from .localnet import LocalNetwork

def rnd(): return secrets.randbelow(secp.N - 1) + 1

async def bench(reps=5):
    rows = []
    async with LocalNetwork(10) as net:
        c = CustodyClient(); nodes = await c.discover(net.bootstrap)
        for t, n in [(2, 3), (3, 5), (4, 7), (7, 10)]:
            ts, tr, tf = [], [], []
            for i in range(reps):
                s = rnd(); a = time.perf_counter()
                m = await c.store(f"b{t}{n}{i}", s, t, n, nodes); b = time.perf_counter()
                assert await c.recover(m) == s; d = time.perf_counter()
                await c.refresh(m); e = time.perf_counter()
                ts.append(b - a); tr.append(d - b); tf.append(e - d)
            rows.append({"t": t, "n": n, "store_ms": 1e3 * st.mean(ts), "recover_ms": 1e3 * st.mean(tr), "refresh_ms": 1e3 * st.mean(tf)})
    return rows

async def fault_tolerance(t=4, n=7):
    rows = []
    for down in range(0, n + 1):
        async with LocalNetwork(n) as net:
            c = CustodyClient(); nodes = await c.discover(net.bootstrap)
            s = rnd(); m = await c.store("ft", s, t, n, nodes)
            for nd in net.nodes[n - down:] if down else []: await nd.stop()
            try: ok = (await c.recover(m, timeout=1)) == s
            except CustodyError: ok = False
        rows.append({"nodes_down": down, "recovered": ok, "expected": down <= n - t})
    return rows

async def byzantine(t=4, n=7):
    rows = []
    for bad in range(0, n - t + 2):
        async with LocalNetwork(n) as net:
            c = CustodyClient(); nodes = await c.discover(net.bootstrap)
            s = rnd(); m = await c.store("bz", s, t, n, nodes)
            for nd in net.nodes[:bad]: nd.byzantine = True
            try: ok = (await c.recover(m)) == s
            except CustodyError: ok = False
        rows.append({"corrupt_nodes": bad, "recovered": ok})
    return rows

async def main():
    res = {"benchmark": await bench(), "fault_tolerance_t4_n7": await fault_tolerance(),
           "byzantine_t4_n7": await byzantine()}
    json.dump(res, open("results.json", "w"), indent=2)
    md = ["# Evaluation results (localhost, 10 in-process nodes)\n", "## Latency (mean of 5, ms)\n",
          "| t | n | store | recover | refresh |", "|---|---|---|---|---|"]
    md += [f"| {r['t']} | {r['n']} | {r['store_ms']:.0f} | {r['recover_ms']:.0f} | {r['refresh_ms']:.0f} |" for r in res["benchmark"]]
    md += ["\n## Crash fault tolerance (t=4, n=7)\n", "| nodes down | recovered | expected |", "|---|---|---|"]
    md += [f"| {r['nodes_down']} | {r['recovered']} | {r['expected']} |" for r in res["fault_tolerance_t4_n7"]]
    md += ["\n## Byzantine nodes returning corrupted shares (t=4, n=7)\n", "| corrupt nodes | recovered |", "|---|---|"]
    md += [f"| {r['corrupt_nodes']} | {r['recovered']} |" for r in res["byzantine_t4_n7"]]
    open("results.md", "w").write("\n".join(md) + "\n"); print("\n".join(md))

if __name__ == "__main__": asyncio.run(main())
