# Distributed Key Custody Network

An Python mini-project that splits a secp256k1 private-key scalar into `t-of-n` Shamir shares, verifies shares with Feldman commitments, encrypts each share to a validator node, and recovers the key only after collecting a threshold of valid shares.


## Features

- Shamir threshold secret sharing over the secp256k1 group order.
- Feldman verifiable commitments to detect inconsistent shares.
- Per-node share encryption using ephemeral X25519, HKDF-SHA256, and AES-256-GCM.
- Ed25519-signed requests, timestamp checks, and per-process nonce replay protection.
- Async TCP nodes and basic gossip peer discovery.
- Threshold recovery, share refresh, tests, and local benchmark harness.
- Atomic replacement when persisting the node's JSON store.

## Repository layout

```text
distributed-key-custody/
├── keycustody/
│   ├── __init__.py
│   ├── secp.py          # Secp256k1 point arithmetic
│   ├── feldman.py       # Shamir split/combine, Feldman verification, refresh
│   ├── ecies.py         # X25519 + HKDF + AES-GCM envelope
│   ├── net.py           # Length-prefixed JSON and TCP RPC
│   ├── node.py          # Validator server, auth, storage, gossip
│   ├── client.py        # Store, recover, refresh client
│   ├── localnet.py      # Local test network
│   ├── tests.py         # Automated tests
│   ├── evaluate.py      # Benchmark and fault-test harness
│   └── cli.py           # Command-line interface
├── docs/
│   └── THREAT_MODEL.md
├── requirements.txt
├── pyproject.toml
└── README.md
```

## Setup

Python 3.10+ is recommended.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

## Test

Run from the repository root:

```bash
python -m unittest keycustody.tests -v
```

## Local multi-node demonstration

Open separate terminals from the repository root. Start one bootstrap node and then additional nodes:

```bash
# Terminal 1
python -m keycustody.cli node --host 127.0.0.1 --port 9001 --data node-data/n1
# Terminal 2
python -m keycustody.cli node --host 127.0.0.1 --port 9002 --data node-data/n2 --bootstrap 127.0.0.1:9001
# Terminal 3
python -m keycustody.cli node --host 127.0.0.1 --port 9003 --data node-data/n3 --bootstrap 127.0.0.1:9001
```

Start at least `n` nodes before running `store`. Example for a 2-of-3 demo:

```bash
python -m keycustody.cli store --bootstrap 127.0.0.1:9001 -t 2 -n 3 --manifest manifest.json
python -m keycustody.cli recover --manifest manifest.json
python -m keycustody.cli refresh --manifest manifest.json
python -m keycustody.cli recover --manifest manifest.json
```

The CLI prints the recovered private-key scalar for demonstration. Never paste a real key into this demo. The owner identity private key is written to `owner.key`; protect and delete demo files when finished.

## Evaluation

```bash
python -m keycustody.evaluate
```

This writes `results.json` and `results.md` in the current working directory.

## Important refresh limitation

After all nodes acknowledge a refresh, the client asks them to remove older versions from local storage. This is best-effort operational cleanup, not cryptographic revocation of copies previously stolen by an attacker. 