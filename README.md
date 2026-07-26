# IoT-Lightweight-Crypto-Security
Python prototype securing IoT sensor-to-gateway telemetry with X25519, HKDF, AES-GCM &amp; ChaCha20-Poly1305 — benchmarked against plaintext with full replay/tamper testing. Master's thesis project.
# Securing IoT Networks Using Lightweight Cryptographic Protocols

Master's thesis project (Vistula University, Warsaw — Computer Engineering, Cybersecurity specialization). A working Python prototype that secures IoT sensor-to-gateway telemetry using lightweight authenticated encryption, benchmarked against a plaintext baseline.

## 🎯 Problem
IoT devices often process sensitive data while running on limited memory, processing power, and battery. Traditional cryptography can secure communication but is frequently too heavy for constrained nodes. This project designs and tests a lightweight security profile for node-to-gateway telemetry that protects against tampering and replay attacks without adding significant processing delay.

## 🏗️ Architecture
- **Session key agreement:** X25519 (elliptic-curve Diffie-Hellman)
- **Key derivation:** HKDF-SHA256, bound to algorithm name, direction, and epoch (prevents raw shared-secret reuse)
- **Authenticated encryption:** AES-GCM and ChaCha20-Poly1305 (compared head-to-head)
- **Replay protection:** per-message counter, checked by the gateway before any decryption is attempted
- **Metadata protection:** associated data (device ID, algorithm, epoch, message type) is authenticated but not encrypted, so it can't be silently modified even though it stays visible for routing

**Components:**
- `SensorNode` — builds telemetry payloads, encrypts, and sends protected packets
- `Gateway` — checks the counter, verifies the authentication tag, decrypts only if verification passes

Implemented in Python using the `cryptography` library (standard, audited primitives — no custom crypto).

## 📊 Benchmark Results
Tested with 1,000 messages, 64-byte payload setting (avg. 88.79 bytes after JSON encoding):

| Metric | Plaintext | AES-GCM | ChaCha20-Poly1305 |
|---|---|---|---|
| Avg. protected message size | 88.79 bytes | 104.79 bytes | 104.79 bytes |
| Avg. overhead | 0 bytes | 16 bytes | 16 bytes |
| Avg. encryption time | 0.0263 ms | 0.0423 ms | 0.0440 ms |
| Avg. decryption time | 0 ms | 0.0109 ms | 0.0130 ms |
| Total wall-clock (1,000 msgs) | 29.51 ms | 79.36 ms | 83.96 ms |
| Peak memory | 43.19 KB | 137.53 KB | 137.26 KB |

**Takeaway:** both AEAD profiles add a fixed 16-byte overhead (the auth tag) and roughly triple processing time versus plaintext — but the absolute cost stays small. AES-GCM was marginally faster than ChaCha20-Poly1305 in this environment.

## 🔒 Security Testing
Three attack simulations were run against the prototype:

| Test | Result |
|---|---|
| Replay attack (resending an accepted packet) | ✅ Passed — repeated counter rejected |
| Tamper detection (modified ciphertext) | ✅ Passed — AEAD tag verification failed as expected |
| Associated data binding (modified metadata) | ✅ Passed — gateway rejected the altered packet |

## ⚠️ Scope & Limitations
This is a controlled prototype, not a certified product. It doesn't include device certificates or a full PKI for onboarding — production deployment would need authenticated key provisioning, hardware testing, and energy/network-loss analysis at scale.

## 🛠️ Tech Stack
`Python` · `cryptography` library · X25519 · HKDF-SHA256 · AES-GCM · ChaCha20-Poly1305

---
*Full methodology, threat model, and related-work analysis available in the complete thesis document.*
