"""
=======================================================================
CLIENT SIDE - Reliable Group Notification System over UDP
=======================================================================
Computer Networks - Jackfruit Mini Project | Client Side

Security:
  ALL packets (JOIN, ACK, LEAVE) are encrypted with AES-256 CBC before
  sending. All received packets (JOIN-OK, NOTIFY) are decrypted before
  processing. No plaintext is visible on the wire.

How to run:
  Terminal 2: python3 client.py 5006 Client-A
  Terminal 3: python3 client.py 5007 Client-B
  Terminal 4: python3 client.py 5008 Client-C
=======================================================================
"""

import socket
import random
import time
import threading
import sys

from protocol import (
    SERVER_IP, SERVER_PORT, ACK_TIMEOUT, LOSS_PROB,
    make_join, make_ack, make_leave,
    parse_notify, parse_any,
    log
)

# ───────────────────────────────────────────────────────────────────
# CONFIGURATION
# ───────────────────────────────────────────────────────────────────
UDP_RECV_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5006
CLIENT_NAME   = sys.argv[2]    if len(sys.argv) > 2 else "Client-A"


# ───────────────────────────────────────────────────────────────────
# PERFORMANCE TRACKING
# ───────────────────────────────────────────────────────────────────
stats = {
    "total_received" : 0,
    "dropped"        : 0,
    "acked"          : 0,
    "duplicates"     : 0,
    "out_of_order"   : 0,
    "latencies_ms"   : [],
    "start_time"     : None,
}
expected_seq = 1
seen_seqs    = set()
stats_lock   = threading.Lock()


# ───────────────────────────────────────────────────────────────────
# HELPERS
# ───────────────────────────────────────────────────────────────────
def simulate_drop():
    return random.random() < LOSS_PROB


def check_seq(seq):
    """Track sequence numbers to detect duplicates and out-of-order packets."""
    global expected_seq
    if seq in seen_seqs:
        with stats_lock:
            stats["duplicates"] += 1
        return "duplicate"
    if seq != expected_seq:
        log(f"  ⚠  OUT OF ORDER: got SEQ {seq}, expected {expected_seq}")
        log(f"     Packets {expected_seq}..{seq-1} may be lost!")
        with stats_lock:
            stats["out_of_order"] += 1
        expected_seq = seq + 1
        return "out_of_order"
    expected_seq += 1
    return "normal"


# ───────────────────────────────────────────────────────────────────
# CONTROL MESSAGES — all encrypted via protocol.py
# ───────────────────────────────────────────────────────────────────
def send_join(udp_sock):
    """
    Send encrypted JOIN to server. Wait for encrypted JOIN-OK reply.
    Retries up to 3 times if no response.
    """
    for attempt in range(1, 4):
        udp_sock.sendto(
            make_join(CLIENT_NAME, UDP_RECV_PORT),
            (SERVER_IP, SERVER_PORT)
        )
        log(f"  [AES-256] JOIN sent → {SERVER_IP}:{SERVER_PORT} (attempt {attempt})")

        udp_sock.settimeout(ACK_TIMEOUT)
        try:
            reply, _ = udp_sock.recvfrom(1024)
            decoded   = parse_any(reply)         # decrypt JOIN-OK
            log(f"Server: {decoded}")
            return True
        except socket.timeout:
            log(f"No reply within {ACK_TIMEOUT}s, retrying...")
        finally:
            udp_sock.settimeout(None)

    log("ERROR: Server did not respond after 3 JOIN attempts.")
    return False


def send_ack(udp_sock, seq, lock):
    """Send encrypted ACK back to server."""
    with lock:
        try:
            udp_sock.sendto(make_ack(seq), (SERVER_IP, SERVER_PORT))
            with stats_lock:
                stats["acked"] += 1
            log(f"  ✓  ACK:{seq} sent [AES-256]")
        except Exception as e:
            log(f"  ✗  Failed to send ACK:{seq} — {e}")


def send_leave(udp_sock, lock):
    """Send encrypted LEAVE to server."""
    with lock:
        try:
            udp_sock.sendto(
                make_leave(CLIENT_NAME, UDP_RECV_PORT),
                (SERVER_IP, SERVER_PORT)
            )
            log("  [AES-256] LEAVE sent to server.")
        except Exception:
            pass


# ───────────────────────────────────────────────────────────────────
# RECEIVE LOOP — decrypts all incoming packets
# ───────────────────────────────────────────────────────────────────
def receive_loop(udp_sock, udp_lock):
    log(f"Listening for notifications on port {UDP_RECV_PORT}...")
    log(f"Simulated packet loss : {int(LOSS_PROB*100)}%")
    log(f"Encryption            : AES-256 CBC\n")

    while True:
        try:
            raw, addr = udp_sock.recvfrom(4096)
            recv_time = time.time()

            # Skip any stray plaintext control messages
            try:
                plaintext = parse_any(raw)
                if plaintext.startswith("JOIN") or plaintext.startswith("LEAVE"):
                    continue
            except Exception:
                pass

            with stats_lock:
                stats["total_received"] += 1

            # Decrypt and parse NOTIFY packet
            seq, msg, sent_time = parse_notify(raw)

            if seq is None:
                log("Unreadable / non-NOTIFY packet, skipping.")
                continue

            log("─" * 50)
            log(f"PACKET [DECRYPTED]  SEQ:{seq}  from {addr[0]}")

            if simulate_drop():
                log(f"  ✗  DROPPED (simulated) — server will retransmit SEQ {seq}")
                with stats_lock:
                    stats["dropped"] += 1
                continue

            status = check_seq(seq)

            if status == "duplicate":
                log(f"  ⚠  DUPLICATE SEQ {seq} — sending ACK anyway")
                send_ack(udp_sock, seq, udp_lock)
                continue

            log(f"  📢  NOTIFICATION: {msg}")
            seen_seqs.add(seq)

            latency_ms = (recv_time - sent_time) * 1000
            with stats_lock:
                stats["latencies_ms"].append(latency_ms)
            log(f"  ⏱  Latency: {latency_ms:.2f} ms")

            threading.Thread(
                target=send_ack,
                args=(udp_sock, seq, udp_lock),
                daemon=True
            ).start()

        except OSError:
            break
        except Exception as e:
            log(f"Receive error: {e}")


# ───────────────────────────────────────────────────────────────────
# PERFORMANCE REPORT
# ───────────────────────────────────────────────────────────────────
def print_performance_report():
    elapsed = time.time() - (stats["start_time"] or time.time())
    lats    = stats["latencies_ms"]

    print("\n" + "=" * 52)
    print("         PERFORMANCE EVALUATION REPORT")
    print("=" * 52)
    print(f"  Client name             : {CLIENT_NAME}")
    print(f"  UDP port                : {UDP_RECV_PORT}")
    print(f"  Encryption              : AES-256 CBC")
    print(f"  Session duration        : {elapsed:.1f} seconds")
    print(f"  Total packets arrived   : {stats['total_received']}")
    print(f"  Packets dropped (sim)   : {stats['dropped']}")
    print(f"  ACKs sent               : {stats['acked']}")
    print(f"  Duplicate packets       : {stats['duplicates']}")
    print(f"  Out-of-order packets    : {stats['out_of_order']}")
    if lats:
        print(f"  Avg latency             : {sum(lats)/len(lats):.2f} ms")
        print(f"  Min latency             : {min(lats):.2f} ms")
        print(f"  Max latency             : {max(lats):.2f} ms")
    received = stats["total_received"]
    dropped  = stats["dropped"]
    if received > 0:
        loss_pct = (dropped / received) * 100
        succ_pct = ((received - dropped) / received) * 100
        print(f"  Effective loss rate     : {loss_pct:.1f}%")
        print(f"  Delivery success rate   : {succ_pct:.1f}%")
    print("=" * 52)


# ───────────────────────────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────────────────────────
def main():
    stats["start_time"] = time.time()
    log(f"Starting {CLIENT_NAME} on UDP port {UDP_RECV_PORT}")
    log(f"Encryption: AES-256 CBC (all packets)")

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("", UDP_RECV_PORT))
    log(f"UDP socket bound to port {UDP_RECV_PORT}")

    udp_lock = threading.Lock()

    joined = send_join(udp_sock)
    if not joined:
        udp_sock.close()
        return

    receiver = threading.Thread(
        target=receive_loop,
        args=(udp_sock, udp_lock),
        daemon=True
    )
    receiver.start()

    log("Press Ctrl+C to disconnect.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("\nDisconnecting...")
        send_leave(udp_sock, udp_lock)
        print_performance_report()
        udp_sock.close()
        log("Goodbye!")


if __name__ == "__main__":
    main()
