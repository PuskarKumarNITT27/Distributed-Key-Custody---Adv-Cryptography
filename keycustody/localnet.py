import asyncio
from .node import Node

class LocalNetwork:
    """n in-process nodes on localhost TCP ports, bootstrapped via node 0, fully gossiped."""
    def __init__(self, n, gossip_interval=0.2, data_root=None):
        self.n, self.gi, self.root, self.nodes = n, gossip_interval, data_root, []
    async def __aenter__(self):
        first = await Node(data_dir=self._d(0), gossip_interval=self.gi).start()
        self.nodes = [first]
        for i in range(1, self.n):
            self.nodes.append(await Node(data_dir=self._d(i), bootstrap=[first.info()["addr"]], gossip_interval=self.gi).start())
        for _ in range(60):
            if all(len(nd.peers) == self.n - 1 for nd in self.nodes): break
            await asyncio.sleep(0.1)
        return self
    def _d(self, i): return f"{self.root}/node{i}" if self.root else None
    @property
    def bootstrap(self): return tuple(self.nodes[0].info()["addr"])
    async def __aexit__(self, *a):
        for nd in self.nodes: await nd.stop()
