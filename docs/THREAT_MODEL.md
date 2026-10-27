# Threat model and security limitations

## Intended educational guarantees

- Shamir sharing: fewer than `t` shares do not determine the secret under the scheme's mathematical assumptions.
- Feldman verification: a share inconsistent with the published coefficient commitments can be rejected.
- AEAD envelope: AES-GCM detects ciphertext or associated-data modification; X25519 derives a per-envelope key through HKDF-SHA256.
- Request signatures: Ed25519 signatures authenticate request contents; timestamps and a nonce cache provide basic replay resistance.
- Availability: recovery can succeed when at least `t` reachable nodes return valid shares.

## Assumptions and limitations

- The client is a trusted dealer and temporarily holds the complete secret during storage and recovery.
- Node discovery is not Sybil-resistant. Node public keys are not certified by a trust authority.
- The nonce cache is in memory, so replay state is not durable across process restarts.
- TCP connections are not protected with TLS. Payloads are signed or encrypted selectively, but metadata remains observable.
- The pure-Python secp256k1 implementation is not constant-time and is not suitable for production private-key operations.
- The node's X25519 private key is stored in a local file. Filesystem permissions do not replace an OS keystore or HSM.
- The client manifest is security-sensitive metadata and should be backed up and protected for integrity.
- Refresh cleanup cannot erase external copies of old shares. If an adversary already copied `t` shares from the same epoch, refreshing nodes cannot make those copies mathematically useless.
- This project does not implement distributed key generation, threshold signing, formal Byzantine consensus, or production-grade membership management.

## Evaluation scope

The automated tests use local TCP servers. They test functional behavior and selected failure cases, not security against a fully adaptive network adversary. Performance figures should be measured by running the included evaluation script on the target machine.
