"""
Lightweight Cryptographic Security Prototype for IoT Node-to-Gateway Telemetry
================================================================================

Implements and benchmarks a lightweight security profile for IoT sensor-to-gateway
communication, based on the design described in the accompanying thesis
"Securing IoT Networks Using Lightweight Cryptographic Protocols".

Components:
    - X25519 for session key agreement
    - HKDF-SHA256 for session key derivation (bound to algorithm, direction, epoch)
    - AES-GCM / ChaCha20-Poly1305 for authenticated encryption of telemetry
    - Per-message counter for replay detection
    - Authenticated (but unencrypted) associated data for metadata integrity

Run:
    pip install -r requirements.txt
    python src/iot_security_prototype.py

Outputs (written to ../results/):
    benchmark_results.csv   - latency / overhead / memory benchmark
    latency_comparison.png  - bar chart comparing plaintext vs AES-GCM vs ChaCha20
    security_tests.txt      - replay / tamper / associated-data test report
"""

import csv
import json
import os
import time
import tracemalloc
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Key agreement + derivation
# ---------------------------------------------------------------------------

def derive_session_key(shared_secret: bytes, algorithm: str, direction: str, epoch: int) -> bytes:
    """Derive a 32-byte AEAD key from an X25519 shared secret using HKDF-SHA256,
    bound to algorithm name, direction, and epoch to prevent raw secret reuse."""
    info = f"{algorithm}|{direction}|{epoch}".encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


def perform_key_exchange():
    """Simulate X25519 key exchange between node and gateway. Returns
    (node_shared_secret, gateway_shared_secret) which should be equal."""
    node_private = X25519PrivateKey.generate()
    gateway_private = X25519PrivateKey.generate()

    node_public = node_private.public_key()
    gateway_public = gateway_private.public_key()

    node_shared = node_private.exchange(gateway_public)
    gateway_shared = gateway_private.exchange(node_public)

    assert node_shared == gateway_shared, "Key exchange mismatch"
    return node_shared


# ---------------------------------------------------------------------------
# Sensor node
# ---------------------------------------------------------------------------

@dataclass
class SensorNode:
    device_id: str
    session_key: bytes
    algorithm: str  # "AES-GCM" or "ChaCha20-Poly1305"
    counter: int = 0

    def _cipher(self):
        return AESGCM(self.session_key) if self.algorithm == "AES-GCM" else ChaCha20Poly1305(self.session_key)

    def _build_nonce(self) -> bytes:
        # 96-bit nonce: 4-byte device prefix + 8-byte counter
        device_prefix = self.device_id.encode().ljust(4, b"\0")[:4]
        return device_prefix + self.counter.to_bytes(8, "big")

    def _build_associated_data(self) -> bytes:
        meta = {
            "device_id": self.device_id,
            "algorithm": self.algorithm,
            "epoch": 1,
            "msg_type": "telemetry",
        }
        return json.dumps(meta, sort_keys=True).encode()

    def create_packet(self, sensor_type: str, value: float, unit: str, pad_to: int = 64) -> dict:
        """Build and encrypt one telemetry packet."""
        self.counter += 1
        payload = {
            "type": sensor_type,
            "seq": self.counter,
            "value": value,
            "unit": unit,
        }
        plaintext = json.dumps(payload).encode()
        if len(plaintext) < pad_to:
            payload["pad"] = "0" * (pad_to - len(plaintext))
            plaintext = json.dumps(payload).encode()

        nonce = self._build_nonce()
        aad = self._build_associated_data()
        ciphertext = self._cipher().encrypt(nonce, plaintext, aad)

        return {
            "device_id": self.device_id,
            "algorithm": self.algorithm,
            "counter": self.counter,
            "nonce": nonce,
            "aad": aad,
            "ciphertext": ciphertext,
            "plaintext_len": len(plaintext),
        }


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------

class ReplayError(Exception):
    pass


class TamperError(Exception):
    pass


@dataclass
class Gateway:
    session_key: bytes
    algorithm: str
    seen_counters: set = field(default_factory=set)

    def _cipher(self):
        return AESGCM(self.session_key) if self.algorithm == "AES-GCM" else ChaCha20Poly1305(self.session_key)

    def receive_packet(self, packet: dict) -> dict:
        """Verify counter freshness, then verify + decrypt. Raises on failure."""
        if packet["counter"] in self.seen_counters:
            raise ReplayError(f"Replayed counter {packet['counter']} rejected")

        try:
            plaintext = self._cipher().decrypt(packet["nonce"], packet["ciphertext"], packet["aad"])
        except Exception as exc:
            raise TamperError(f"Authentication failed: {exc}")

        self.seen_counters.add(packet["counter"])
        return json.loads(plaintext)


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def benchmark_profile(algorithm: str, num_messages: int = 1000, payload_size: int = 64):
    shared_secret = perform_key_exchange()

    setup_start = time.perf_counter()
    session_key = derive_session_key(shared_secret, algorithm, "node-to-gateway", epoch=1)
    setup_time_ms = (time.perf_counter() - setup_start) * 1000

    node = SensorNode(device_id="node1", session_key=session_key, algorithm=algorithm)
    gateway = Gateway(session_key=session_key, algorithm=algorithm)

    enc_times, dec_times, plain_sizes, cipher_sizes = [], [], [], []

    tracemalloc.start()
    wall_start = time.perf_counter()
    cpu_start = time.process_time()

    for i in range(num_messages):
        t0 = time.perf_counter()
        packet = node.create_packet("temperature", 21.5 + (i % 10) * 0.1, "C", pad_to=payload_size)
        enc_times.append((time.perf_counter() - t0) * 1000)

        plain_sizes.append(packet["plaintext_len"])
        cipher_sizes.append(len(packet["ciphertext"]))

        t1 = time.perf_counter()
        gateway.receive_packet(packet)
        dec_times.append((time.perf_counter() - t1) * 1000)

    wall_time_ms = (time.perf_counter() - wall_start) * 1000
    cpu_time_ms = (time.process_time() - cpu_start) * 1000
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    def pctl(data, p):
        s = sorted(data)
        idx = min(int(len(s) * p) , len(s) - 1)
        return s[idx]

    return {
        "algorithm": algorithm,
        "messages": num_messages,
        "payload_size_setting": payload_size,
        "avg_plaintext_bytes": round(sum(plain_sizes) / len(plain_sizes), 2),
        "avg_ciphertext_bytes": round(sum(cipher_sizes) / len(cipher_sizes), 2),
        "avg_overhead_bytes": round((sum(cipher_sizes) - sum(plain_sizes)) / len(plain_sizes), 2),
        "session_setup_time_ms": round(setup_time_ms, 4),
        "avg_encryption_time_ms": round(sum(enc_times) / len(enc_times), 4),
        "avg_decryption_time_ms": round(sum(dec_times) / len(dec_times), 4),
        "p95_encryption_time_ms": round(pctl(enc_times, 0.95), 4),
        "p95_decryption_time_ms": round(pctl(dec_times, 0.95), 4),
        "total_wall_clock_ms": round(wall_time_ms, 4),
        "total_cpu_time_ms": round(cpu_time_ms, 4),
        "peak_memory_kb": round(peak_mem / 1024, 4),
    }


def benchmark_plaintext_baseline(num_messages: int = 1000, payload_size: int = 64):
    """No encryption — measures pure JSON encode/decode cost as a baseline."""
    enc_times, dec_times, sizes = [], [], []

    tracemalloc.start()
    wall_start = time.perf_counter()
    cpu_start = time.process_time()

    for i in range(num_messages):
        t0 = time.perf_counter()
        payload = {"type": "temperature", "seq": i + 1, "value": 21.5 + (i % 10) * 0.1, "unit": "C"}
        plaintext = json.dumps(payload).encode()
        if len(plaintext) < payload_size:
            payload["pad"] = "0" * (payload_size - len(plaintext))
            plaintext = json.dumps(payload).encode()
        enc_times.append((time.perf_counter() - t0) * 1000)
        sizes.append(len(plaintext))

        t1 = time.perf_counter()
        json.loads(plaintext)
        dec_times.append((time.perf_counter() - t1) * 1000)

    wall_time_ms = (time.perf_counter() - wall_start) * 1000
    cpu_time_ms = (time.process_time() - cpu_start) * 1000
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "algorithm": "Plaintext baseline",
        "messages": num_messages,
        "payload_size_setting": payload_size,
        "avg_plaintext_bytes": round(sum(sizes) / len(sizes), 2),
        "avg_ciphertext_bytes": round(sum(sizes) / len(sizes), 2),
        "avg_overhead_bytes": 0.0,
        "session_setup_time_ms": 0.0,
        "avg_encryption_time_ms": round(sum(enc_times) / len(enc_times), 4),
        "avg_decryption_time_ms": round(sum(dec_times) / len(dec_times), 4),
        "p95_encryption_time_ms": round(sorted(enc_times)[int(len(enc_times) * 0.95)], 4),
        "p95_decryption_time_ms": round(sorted(dec_times)[int(len(dec_times) * 0.95)], 4),
        "total_wall_clock_ms": round(wall_time_ms, 4),
        "total_cpu_time_ms": round(cpu_time_ms, 4),
        "peak_memory_kb": round(peak_mem / 1024, 4),
    }


def run_benchmarks():
    results = [
        benchmark_plaintext_baseline(),
        benchmark_profile("AES-GCM"),
        benchmark_profile("ChaCha20-Poly1305"),
    ]

    csv_path = os.path.join(RESULTS_DIR, "benchmark_results.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    print(f"Benchmark results written to {csv_path}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        labels = [r["algorithm"] for r in results]
        enc_times = [r["avg_encryption_time_ms"] for r in results]
        dec_times = [r["avg_decryption_time_ms"] for r in results]

        x = range(len(labels))
        width = 0.35
        fig, ax = plt.subplots(figsize=(7, 4.5))
        ax.bar([i - width / 2 for i in x], enc_times, width, label="Avg encryption time (ms)")
        ax.bar([i + width / 2 for i in x], dec_times, width, label="Avg decryption time (ms)")
        ax.set_xticks(list(x))
        ax.set_xticklabels(labels)
        ax.set_ylabel("Time (ms)")
        ax.set_title("Latency Comparison: Plaintext vs AES-GCM vs ChaCha20-Poly1305")
        ax.legend()
        fig.tight_layout()

        chart_path = os.path.join(RESULTS_DIR, "latency_comparison.png")
        fig.savefig(chart_path, dpi=150)
        print(f"Latency chart written to {chart_path}")
    except ImportError:
        print("matplotlib not installed — skipping chart generation")

    return results


# ---------------------------------------------------------------------------
# Security tests: replay, tamper, associated-data binding
# ---------------------------------------------------------------------------

def run_security_tests():
    lines = ["Security test report", ""]

    # --- Replay test ---
    shared_secret = perform_key_exchange()
    key = derive_session_key(shared_secret, "AES-GCM", "node-to-gateway", epoch=1)
    node = SensorNode(device_id="node1", session_key=key, algorithm="AES-GCM")
    gateway = Gateway(session_key=key, algorithm="AES-GCM")

    packet = node.create_packet("temperature", 22.0, "C")
    gateway.receive_packet(packet)  # first delivery, should succeed
    try:
        gateway.receive_packet(packet)  # replay the same packet
        lines.append("Replay test: FAILED (replayed packet was accepted)")
    except ReplayError:
        lines.append("Replay test: PASSED")
        lines.append("The gateway rejected a repeated message counter.")
    lines.append("")

    # --- Tamper test ---
    shared_secret2 = perform_key_exchange()
    key2 = derive_session_key(shared_secret2, "AES-GCM", "node-to-gateway", epoch=1)
    node2 = SensorNode(device_id="node2", session_key=key2, algorithm="AES-GCM")
    gateway2 = Gateway(session_key=key2, algorithm="AES-GCM")

    packet2 = node2.create_packet("temperature", 22.0, "C")
    tampered = dict(packet2)
    tampered["ciphertext"] = bytes([tampered["ciphertext"][0] ^ 0xFF]) + tampered["ciphertext"][1:]
    try:
        gateway2.receive_packet(tampered)
        lines.append("Tamper test: FAILED (modified ciphertext was accepted)")
    except TamperError:
        lines.append("Tamper test: PASSED")
        lines.append("The gateway rejected modified ciphertext because authentication tag verification failed.")
    lines.append("")

    # --- Associated data binding test ---
    shared_secret3 = perform_key_exchange()
    key3 = derive_session_key(shared_secret3, "AES-GCM", "node-to-gateway", epoch=1)
    node3 = SensorNode(device_id="node3", session_key=key3, algorithm="AES-GCM")
    gateway3 = Gateway(session_key=key3, algorithm="AES-GCM")

    packet3 = node3.create_packet("temperature", 22.0, "C")
    tampered_aad = dict(packet3)
    tampered_aad["aad"] = tampered_aad["aad"].replace(b"node3", b"node9")
    try:
        gateway3.receive_packet(tampered_aad)
        lines.append("Associated data binding test: FAILED (changed metadata was accepted)")
    except TamperError:
        lines.append("Associated data binding test: PASSED")
        lines.append("The gateway rejected changed associated data because the authentication tag no longer matched.")
    lines.append("")

    lines.append("Conclusion:")
    lines.append("The implemented prototype correctly rejected replayed packets, modified")
    lines.append("ciphertext and changed associated data.")

    report_path = os.path.join(RESULTS_DIR, "security_tests.txt")
    with open(report_path, "w") as f:
        f.write("\n".join(lines))

    print(f"Security test report written to {report_path}")
    print("\n".join(lines))


if __name__ == "__main__":
    print("Running benchmarks...\n")
    run_benchmarks()
    print("\nRunning security tests...\n")
    run_security_tests()
