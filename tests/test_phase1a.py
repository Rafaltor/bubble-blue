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
from src.security.crypto import decrypt_from_group, encrypt_for_group  # noqa: E402
from src.security.packet import (  # noqa: E402
    build_bb_packet,
    build_routing_header,
    packet_overhead,
    parse_bb_packet,
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


def run_server() -> None:
    # 1. Load config (group_key from env)
    cfg = load_config()
    group_key = cfg.group_key

    # 2. Print "[SERVER] Waiting for encrypted BB packet..."
    print("[SERVER] Waiting for encrypted BB packet...", flush=True)

    replay_filter = ReplayFilter()

    # 4. In on_receive:
    def on_receive(peer_bd_addr: str, data: bytes) -> None:
        try:
            # a. Parse BB packet
            parsed = parse_bb_packet(data)
            rh = parsed["routing_header"]
            hdr = parsed["parsed_header"]

            # b. Print routing info: src, dst, ttl, seq
            print(
                f"[SERVER] RX routing: src={hdr['src']} dst={hdr['dst']} ttl={hdr['ttl']} seq={hdr['seq']}",
                flush=True,
            )

            aad = routing_header_aad(rh)
            plaintext = decrypt_from_group(
                group_key,
                parsed["session_key_enc"],
                parsed["nonce"],
                parsed["ciphertext"],
                aad,
            )

            # Post-decryption checks: timestamp + anti-replay
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

            # e. Print decrypted message
            try:
                msg = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                msg = repr(plaintext)
            print(f"[SERVER] Decrypted message: {msg}", flush=True)

            # f. Print success
            print("✅ Phase 1A SUCCESS: message decrypted and verified", flush=True)
        except InvalidTag:
            print("❌ Decryption FAILED — wrong key or tampered packet", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"[SERVER] Error handling packet from {peer_bd_addr}: {e}", flush=True)

    # 3. Create L2CAPTransport with on_receive callback
    transport = L2CAPTransport(on_receive=on_receive)

    # 5. Start transport, wait for Ctrl+C
    transport.start()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[SERVER] Stopping...", flush=True)
    finally:
        transport.stop()


def run_client(peer_bd_addr: str) -> None:
    # 1. Load config
    cfg = load_config()
    group_key = cfg.group_key

    # 2. Build routing_header
    routing_header = build_routing_header(
        PKT_DATA,
        src=cfg.local_bd_addr,
        dst=peer_bd_addr,
        ttl=10,
        seq=1,
    )

    # 3. Message
    message = f"Hello BB from {cfg.node_name} — Phase 1A test".encode("utf-8")

    # 4. Encrypt with encrypt_for_group(cfg.group_key, message, routing_header)
    result = encrypt_for_group(group_key, message, routing_header_aad(routing_header))

    # 5. Build complete BB packet
    packet = build_bb_packet(
        routing_header,
        session_key_enc=result["session_key_enc"],
        nonce=result["nonce"],
        ciphertext=result["ciphertext"],
    )

    # 6. Print packet breakdown
    print("📦 Packet breakdown:", flush=True)
    print("   Routing header : 26 bytes (clear)", flush=True)
    print("   Session key enc: 60 bytes", flush=True)
    print("   Nonce          : 12 bytes", flush=True)
    print(f"   Ciphertext+tag : {len(result['ciphertext'])} bytes", flush=True)
    print(f"   Fixed overhead : {packet_overhead()} bytes", flush=True)
    print(f"   Total          : {len(packet)} bytes", flush=True)

    # 7. Send via L2CAPTransport
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

    # 8. Print success
    print(f"✅ Phase 1A: encrypted packet sent to {peer_bd_addr.upper()}", flush=True)


def run_intruder(peer_bd_addr: str) -> None:
    """Send a well-formed BB packet encrypted with a wrong (random) group key."""
    cfg = load_config()
    wrong_key = os.urandom(32)

    print("[INTRUDER] Using random group key (not from .env)", flush=True)

    routing_header = build_routing_header(
        PKT_DATA,
        src=cfg.local_bd_addr,
        dst=peer_bd_addr,
        ttl=10,
        seq=999,
    )

    message = "INTRUDER — wrong group key test".encode("utf-8")
    result = encrypt_for_group(wrong_key, message, routing_header_aad(routing_header))

    packet = build_bb_packet(
        routing_header,
        session_key_enc=result["session_key_enc"],
        nonce=result["nonce"],
        ciphertext=result["ciphertext"],
    )

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
    """Send the same BB packet twice; server should accept then reject replay."""
    cfg = load_config()
    group_key = cfg.group_key

    routing_header = build_routing_header(
        PKT_DATA,
        src=cfg.local_bd_addr,
        dst=peer_bd_addr,
        ttl=10,
        seq=42,
    )

    message = "REPLAY test — same packet sent twice".encode("utf-8")
    result = encrypt_for_group(group_key, message, routing_header_aad(routing_header))

    packet = build_bb_packet(
        routing_header,
        session_key_enc=result["session_key_enc"],
        nonce=result["nonce"],
        ciphertext=result["ciphertext"],
    )

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

