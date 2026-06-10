from __future__ import annotations

import os
import sys
import time

from cryptography.exceptions import InvalidTag

# Ensure project root is importable when running as a script:
#   python3 tests/test_phase1a.py ...
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import PKT_DATA, load_config  # noqa: E402
from src.security.crypto import decrypt_with_key, encrypt_with_key  # noqa: E402
from src.security.keys import derive_packet_key  # noqa: E402
from src.security.packet import (  # noqa: E402
    build_bb_packet,
    build_routing_header,
    packet_overhead,
    parse_bb_packet,
    parse_routing_header,
    routing_header_aad,
    validate_timestamp,
)
from src.security.replay import ReplayFilter  # noqa: E402
from src.transport.l2cap import L2CAPTransport  # noqa: E402


def _usage() -> None:
    print(
        "Usage:\n"
        "  python3 tests/test_phase1a.py server\n"
        "  python3 tests/test_phase1a.py client <PEER_BD_ADDR>\n"
        "  python3 tests/test_phase1a.py intruder <PEER_BD_ADDR>\n"
        "  python3 tests/test_phase1a.py replay <PEER_BD_ADDR>",
        flush=True,
    )


def _build_encrypted_packet(
    group_key: bytes,
    routing_header: bytes,
    message: bytes,
) -> bytes:
    hdr = parse_routing_header(routing_header)
    packet_key = derive_packet_key(
        group_key,
        hdr["src"],
        int(hdr["seq"]),
        int(hdr["ts_ms"]),
    )
    enc = encrypt_with_key(packet_key, message, routing_header_aad(routing_header))
    return build_bb_packet(routing_header, enc["ciphertext"])


def _decrypt_packet(group_key: bytes, data: bytes) -> bytes:
    parsed = parse_bb_packet(data)
    hdr = parsed["parsed_header"]
    packet_key = derive_packet_key(
        group_key,
        hdr["src"],
        int(hdr["seq"]),
        int(hdr["ts_ms"]),
    )
    return decrypt_with_key(
        packet_key,
        parsed["ciphertext"],
        routing_header_aad(parsed["routing_header"]),
    )


def run_server() -> None:
    cfg = load_config()
    group_key = cfg.group_key

    print("[SERVER] Waiting for encrypted BB packet...", flush=True)

    replay_filter = ReplayFilter()

    def on_receive(peer_bd_addr: str, data: bytes) -> None:
        try:
            parsed = parse_bb_packet(data)
            rh = parsed["routing_header"]
            hdr = parsed["parsed_header"]

            print(
                f"[SERVER] RX routing: src={hdr['src']} dst={hdr['dst']} ttl={hdr['ttl']} seq={hdr['seq']}",
                flush=True,
            )

            plaintext = _decrypt_packet(group_key, data)

            ts_ms = hdr["ts_ms"]
            if not validate_timestamp(ts_ms):
                print("❌ REJECTED: packet too old/future", flush=True)
                return

            src = hdr["src"]
            seq = hdr["seq"]
            if not replay_filter.check_and_update(src, seq):
                print("❌ REJECTED: replay attack detected", flush=True)
                return

            print(f"✅ seq={seq} accepted", flush=True)

            try:
                msg = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                msg = repr(plaintext)
            print(f"[SERVER] Decrypted message: {msg}", flush=True)
            print("✅ Phase 1A SUCCESS: message decrypted and verified", flush=True)
        except InvalidTag:
            print("❌ Decryption FAILED — wrong key or tampered packet", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"[SERVER] Error handling packet from {peer_bd_addr}: {e}", flush=True)

    transport = L2CAPTransport(on_receive=on_receive)
    transport.start()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[SERVER] Stopping...", flush=True)
    finally:
        transport.stop()


def run_client(peer_bd_addr: str) -> None:
    cfg = load_config()
    group_key = cfg.group_key

    ts_ms = time.time_ns() // 1_000_000
    routing_header = build_routing_header(
        PKT_DATA,
        src=cfg.local_bd_addr,
        dst=peer_bd_addr,
        ttl=10,
        seq=1,
        ts_ms=ts_ms,
    )

    message = f"Hello BB from {cfg.node_name} — Phase 1A test".encode("utf-8")
    enc = encrypt_with_key(
        derive_packet_key(group_key, cfg.local_bd_addr, 1, ts_ms),
        message,
        routing_header_aad(routing_header),
    )
    packet = build_bb_packet(routing_header, enc["ciphertext"])

    print("📦 Packet breakdown:", flush=True)
    print("   Routing header : 26 bytes (clear)", flush=True)
    print(f"   Ciphertext+tag : {len(enc['ciphertext'])} bytes", flush=True)
    print(f"   Fixed overhead : {packet_overhead()} bytes", flush=True)
    print(f"   Total          : {len(packet)} bytes", flush=True)

    transport = L2CAPTransport()
    transport.start()
    try:
        transport.send(peer_bd_addr, packet)
    except OSError as e:
        print(f"❌ Connection error: {e}", flush=True)
        return
    except Exception as e:  # noqa: BLE001
        print(f"❌ Connection error: {e}", flush=True)
        return
    finally:
        transport.stop()

    print(f"✅ Phase 1A: encrypted packet sent to {peer_bd_addr.upper()}", flush=True)


def run_intruder(peer_bd_addr: str) -> None:
    cfg = load_config()
    wrong_key = os.urandom(32)

    print("[INTRUDER] Using random group key (not from .env)", flush=True)

    ts_ms = time.time_ns() // 1_000_000
    routing_header = build_routing_header(
        PKT_DATA,
        src=cfg.local_bd_addr,
        dst=peer_bd_addr,
        ttl=10,
        seq=999,
        ts_ms=ts_ms,
    )

    message = "INTRUDER — wrong group key test".encode("utf-8")
    packet = _build_encrypted_packet(wrong_key, routing_header, message)

    print(f"[INTRUDER] Sending {len(packet)}-byte packet to {peer_bd_addr.upper()}", flush=True)

    transport = L2CAPTransport()
    transport.start()
    try:
        transport.send(peer_bd_addr, packet)
    except OSError as e:
        print(f"❌ Connection error: {e}", flush=True)
        return
    except Exception as e:  # noqa: BLE001
        print(f"❌ Connection error: {e}", flush=True)
        return
    finally:
        transport.stop()

    print(
        f"✅ Intruder packet sent to {peer_bd_addr.upper()} "
        "(server should reject decryption)",
        flush=True,
    )


def run_replay(peer_bd_addr: str) -> None:
    cfg = load_config()
    group_key = cfg.group_key

    ts_ms = time.time_ns() // 1_000_000
    routing_header = build_routing_header(
        PKT_DATA,
        src=cfg.local_bd_addr,
        dst=peer_bd_addr,
        ttl=10,
        seq=42,
        ts_ms=ts_ms,
    )

    message = "REPLAY test — same packet sent twice".encode("utf-8")
    packet = _build_encrypted_packet(group_key, routing_header, message)

    print(f"[REPLAY] Sending identical packet twice to {peer_bd_addr.upper()}", flush=True)
    print("[REPLAY] Expect: first accepted, second rejected as replay", flush=True)

    transport = L2CAPTransport()
    transport.start()
    try:
        transport.send(peer_bd_addr, packet)
        time.sleep(0.5)
        transport.send(peer_bd_addr, packet)
    except OSError as e:
        print(f"❌ Connection error: {e}", flush=True)
        return
    except Exception as e:  # noqa: BLE001
        print(f"❌ Connection error: {e}", flush=True)
        return
    finally:
        transport.stop()

    print(f"✅ Replay test: two identical packets sent to {peer_bd_addr.upper()}", flush=True)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        _usage()
        return 2

    mode = argv[1].lower().strip()
    if mode == "server":
        if len(argv) != 2:
            _usage()
            return 2
        run_server()
        return 0

    if mode == "client":
        if len(argv) != 3:
            _usage()
            return 2
        peer = argv[2]
        run_client(peer)
        return 0

    if mode == "intruder":
        if len(argv) != 3:
            _usage()
            return 2
        peer = argv[2]
        run_intruder(peer)
        return 0

    if mode == "replay":
        if len(argv) != 3:
            _usage()
            return 2
        peer = argv[2]
        run_replay(peer)
        return 0

    _usage()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
