# Distributed Key Custody Network
## Splitting user private keys into encrypted shares across P2P validator nodes

### Abstract
This project demonstrates threshold custody of a secp256k1 private-key scalar. The client splits the secret with Shamir's Secret Sharing, publishes Feldman commitments to enable share verification, encrypts each share to a validator node using ephemeral X25519, HKDF-SHA256 and AES-256-GCM, and distributes shares over asynchronous TCP. Owner requests are signed with Ed25519. A recovery client collects a threshold of valid shares and checks the reconstructed scalar against the committed public key.

### Objectives
- Demonstrate `t-of-n` threshold sharing.
- Detect inconsistent shares using Feldman commitments.
- Protect shares in transit with authenticated encryption.
- Authenticate owner requests and reject replayed requests within the node's in-memory replay window.
- Demonstrate validator discovery, recovery under node failures, and share refresh.
- Provide repeatable tests and local performance measurements.

### Architecture
The client is a trusted dealer. During `store`, it generates the shares and commitments, encrypts each share to the selected validator, and sends a signed request. Nodes decrypt the share internally to verify it against the commitments, then store its encrypted envelope. During `recover`, nodes return shares encrypted to an ephemeral client key. The client verifies each share, combines a threshold subset, and verifies the reconstructed public key. During refresh, the client creates a random zero-constant polynomial, sends encrypted deltas, and updates commitments. After all nodes acknowledge the new version, the client requests removal of older versions from node storage.

### Cryptographic components
- **Shamir secret sharing:** shares are evaluations of a random degree `t-1` polynomial over the secp256k1 group order.
- **Feldman verification:** each polynomial coefficient is represented by a group commitment; nodes and clients can verify share consistency.
- **Share encryption:** X25519 ephemeral key agreement, HKDF-SHA256 key derivation, and AES-256-GCM authenticated encryption.
- **Request authentication:** Ed25519 signatures bind canonical JSON request fields; timestamps and nonces provide basic replay protection.
- **Networking:** asynchronous TCP, length-prefixed JSON messages, bootstrap discovery, and periodic peer gossip.

### Repository and implementation
The `keycustody/` package contains the cryptographic helpers, validator node, client, network transport, CLI, local test network, tests, and evaluation harness. `docs/THREAT_MODEL.md` documents assumptions and limitations. `results.md` and `results.json` contain the evaluation run generated for this submission bundle.

### Evaluation methodology and observed results
The automated test suite was run with `python -m unittest keycustody.tests -v` in Python 3.13. It passed **15 tests** covering curve operations, share split/combine, invalid inputs, tamper detection, envelope encryption, peer discovery, recovery, crash tolerance, invalid shares, owner authentication, replay rejection, and refresh behavior.

The evaluation harness was run using `python -m keycustody.evaluate`. It used 10 in-process localhost TCP nodes and reported mean timings over five runs per threshold/size configuration. This environment measured:

| Threshold (t) | Nodes (n) | Store (ms) | Recover (ms) | Refresh (ms) |
|---:|---:|---:|---:|---:|
| 2 | 3 | 37 | 28 | 55 |
| 3 | 5 | 63 | 49 | 93 |
| 4 | 7 | 75 | 57 | 118 |
| 7 | 10 | 130 | 88 | 207 |

For `t=4, n=7`, recovery succeeded with zero through three nodes down and failed with four or more down. With corrupted shares served by zero through three nodes, recovery succeeded; with four corrupted nodes, recovery failed because fewer than four valid shares remained. These are local functional measurements, not WAN performance results or a formal security proof.

### Security analysis and limitations
The threshold construction is designed so fewer than `t` shares do not determine the secret under Shamir's assumptions. Feldman verification detects shares inconsistent with the published commitments. AES-GCM detects ciphertext tampering, and signed requests provide basic owner authentication.

### Conclusion
The project demonstrates the core workflow of distributed threshold key custody: split, encrypt, distribute, verify, recover, and refresh. The included tests and measurements provide reproducible functional evidence for the tested local scenarios. The implementation should be treated as an educational prototype and not used for real assets or secrets.
