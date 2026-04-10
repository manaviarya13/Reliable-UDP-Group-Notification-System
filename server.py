"""
=======================================================================
SERVER SIDE - Reliable Group Notification System over UDP
=======================================================================
Computer Networks - Jackfruit Mini Project | Server Side

Security:
  ALL packets (JOIN-OK, NOTIFY, ACK) are encrypted with AES-256 CBC
  before sending. All received packets (JOIN, ACK, LEAVE) are decrypted
  before processing. No plaintext is visible on the wire.

How to run:
  1. pip install pycryptodome
  2. python3 server.py
  3. In 3 other terminals:
       python3 client.py 5006 Client-A
       python3 client.py 5007 Client-B
       python3 client.py 5008 Client-C
=======================================================================
"""

import socket
import threading
import time

from protocol import (
    SERVER_IP, SERVER_PORT, BUFFER_SIZE, MAX_RETRIES, ACK_TIMEOUT,
    make_join_ok, make_notify,
    parse_any, parse_join, parse_ack, parse_leave,
    log
)

# ───────────────────────────────────────────────────────────────────
# CONFIGURATION
# ───────────────────────────────────────────────────────────────────
SERVER_BIND_IP = "0.0.0.0"    # listen on all interfaces
TIMEOUT        = ACK_TIMEOUT  # retransmit timeout in seconds


# ───────────────────────────────────────────────────────────────────
# CLIENT REGISTRY
# ───────────────────────────────────────────────────────────────────
clients      = {}             # { (ip, udp_port): {"name": str} }
clients_lock = threading.Lock()


# ───────────────────────────────────────────────────────────────────
# PENDING ACK TRACKER
# ───────────────────────────────────────────────────────────────────
pending_acks = {}             # { ((ip,port), seq): {"data", "retries", "timer"} }
pending_lock = threading.Lock()


# ───────────────────────────────────────────────────────────────────
# SEQUENCE NUMBER
# ───────────────────────────────────────────────────────────────────
server_seq      = 1
server_seq_lock = threading.Lock()


# ───────────────────────────────────────────────────────────────────
# PERFORMANCE STATS
# ───────────────────────────────────────────────────────────────────
stats = {
    "broadcasts"    : 0,
    "total_sent"    : 0,
    "retransmits"   : 0,
    "acks_received" : 0,
    "clients_joined": 0,
    "clients_left"  : 0,
    "start_time"    : None,
}


# ───────────────────────────────────────────────────────────────────
# HELPERS
# ───────────────────────────────────────────────────────────────────
def get_next_seq():
    global server_seq
    with server_seq_lock:
        seq = server_seq
        server_seq += 1
    return seq


# ───────────────────────────────────────────────────────────────────
# JOIN / LEAVE HANDLERS
# ───────────────────────────────────────────────────────────────────
def handle_join(sock, raw: bytes, sender_addr):
    """
    Decrypt JOIN packet, register client, reply with encrypted JOIN-OK.
    JOIN format (plaintext): JOIN:ClientName:UDPPort
    """
    name, udp_port = parse_join(raw)
    if name is None:
        log(f"    Malformed JOIN from {sender_addr}")
        return

    client_key = (sender_addr[0], udp_port)

    with clients_lock:
        if client_key not in clients:
            clients[client_key] = {"name": name}
            stats["clients_joined"] += 1
            log(f"   JOIN  | {name} registered at {client_key} "
                f"| Total: {len(clients)}")
        else:
            log(f"  ℹ  JOIN  | {name} already registered")

    # Reply with encrypted JOIN-OK
    sock.sendto(make_join_ok(name), client_key)


def handle_leave(raw: bytes, sender_addr):
    """
    Decrypt LEAVE packet, remove client, cancel pending retransmits.
    LEAVE format (plaintext): LEAVE:ClientName:UDPPort
    """
    name, udp_port = parse_leave(raw)
    if name is None:
        log(f"    Malformed LEAVE from {sender_addr}")
        return

    client_key = (sender_addr[0], udp_port)

    with clients_lock:
        if client_key in clients:
            del clients[client_key]
            stats["clients_left"] += 1
            log(f"    LEAVE | {name} removed | Total: {len(clients)}")

    with pending_lock:
        keys_to_del = [k for k in pending_acks if k[0] == client_key]
        for k in keys_to_del:
            pending_acks[k]["timer"].cancel()
            del pending_acks[k]


# ───────────────────────────────────────────────────────────────────
# RETRANSMISSION
# ───────────────────────────────────────────────────────────────────
def send_with_retry(sock, encrypted_data: bytes, client_addr, seq):
    """
    Send an encrypted NOTIFY packet.
    If no ACK arrives within TIMEOUT seconds, retransmit.
    Give up after MAX_RETRIES and remove the unresponsive client.
    """
    key = (client_addr, seq)
    sock.sendto(encrypted_data, client_addr)
    stats["total_sent"] += 1
    log(f"  → SEND [AES-256] SEQ:{seq} to {client_addr}")

    def retransmit():
        with pending_lock:
            if key not in pending_acks:
                return
            entry = pending_acks[key]
            if entry["retries"] >= MAX_RETRIES:
                log(f"    MAX RETRIES SEQ:{seq} → {client_addr}. Removing.")
                with clients_lock:
                    clients.pop(client_addr, None)
                del pending_acks[key]
                return
            entry["retries"] += 1
            stats["retransmits"] += 1
            log(f"  ↺  RETRANSMIT SEQ:{seq} → {client_addr} "
                f"(attempt {entry['retries']}/{MAX_RETRIES})")
            sock.sendto(encrypted_data, client_addr)
            t = threading.Timer(TIMEOUT, retransmit)
            entry["timer"] = t
            t.start()

    timer = threading.Timer(TIMEOUT, retransmit)
    with pending_lock:
        pending_acks[key] = {"data": encrypted_data, "retries": 0, "timer": timer}
    timer.start()


def cancel_ack(client_addr, seq):
    """Cancel retransmit timer when ACK is received."""
    key = (client_addr, seq)
    with pending_lock:
        if key in pending_acks:
            pending_acks[key]["timer"].cancel()
            del pending_acks[key]
            stats["acks_received"] += 1
            log(f"    ACK received SEQ:{seq} from {client_addr}")


# ───────────────────────────────────────────────────────────────────
# BROADCAST
# ───────────────────────────────────────────────────────────────────
def broadcast(sock, message):
    """
    Build, encrypt, and send NOTIFY to every registered client.
    Uses make_notify() from protocol.py which encrypts with AES-256.
    """
    with clients_lock:
        current_clients = dict(clients)

    if not current_clients:
        log("[INFO] No clients connected.")
        return

    seq           = get_next_seq()
    encrypted_pkt = make_notify(seq, message)

    stats["broadcasts"] += 1
    log(f"\n{'─'*50}")
    log(f"BROADCAST SEQ:{seq} MSG:'{message}' Clients:{len(current_clients)}")
    log(f"  [AES-256] Packet encrypted before sending")

    for addr, info in current_clients.items():
        log(f"  Sending to {info['name']} @ {addr}")
        send_with_retry(sock, encrypted_pkt, addr, seq)


# ───────────────────────────────────────────────────────────────────
# RECEIVER LOOP
# Decrypts every incoming packet first, then routes by type
# ───────────────────────────────────────────────────────────────────
def receiver_loop(sock):
    log(f"[SERVER] Listening on {SERVER_BIND_IP}:{SERVER_PORT} ...")
    while True:
        try:
            raw, addr = sock.recvfrom(BUFFER_SIZE)

            # Decrypt to identify packet type
            plaintext = parse_any(raw)

            if plaintext.startswith("JOIN"):
                handle_join(sock, raw, addr)

            elif plaintext.startswith("ACK:"):
                seq = parse_ack(raw)
                if seq is not None:
                    cancel_ack(addr, seq)
                else:
                    log(f"    Malformed ACK from {addr}")

            elif plaintext.startswith("LEAVE"):
                handle_leave(raw, addr)

            else:
                log(f"    Unknown packet from {addr}: {plaintext[:60]}")

        except Exception as e:
            log(f"[ERROR] {e}")


# ───────────────────────────────────────────────────────────────────
# PERFORMANCE REPORT
# ───────────────────────────────────────────────────────────────────
def print_performance_report():
    elapsed = time.time() - (stats["start_time"] or time.time())
    print("\n" + "=" * 52)
    print("         SERVER PERFORMANCE REPORT")
    print("=" * 52)
    print(f"  Session duration        : {elapsed:.1f} seconds")
    print(f"  Encryption              : AES-256 CBC")
    print(f"  Total broadcasts        : {stats['broadcasts']}")
    print(f"  Total packets sent      : {stats['total_sent']}")
    print(f"  Retransmissions         : {stats['retransmits']}")
    print(f"  ACKs received           : {stats['acks_received']}")
    print(f"  Clients joined          : {stats['clients_joined']}")
    print(f"  Clients left            : {stats['clients_left']}")
    with clients_lock:
        print(f"  Clients still active    : {len(clients)}")
    print("=" * 52)


# ───────────────────────────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────────────────────────
def main():
    stats["start_time"] = time.time()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SERVER_BIND_IP, SERVER_PORT))

    rx_thread = threading.Thread(target=receiver_loop, args=(sock,), daemon=True)
    rx_thread.start()

    log("=" * 52)
    log("  Reliable Group Notification Server — UDP")
    log(f"  Listening on port : {SERVER_PORT}")
    log(f"  Encryption        : AES-256 CBC (all packets)")
    log("  Type a message + Enter to broadcast.")
    log("  Ctrl+C to stop.\n")

    try:
        while True:
            msg = input("Notification> ").strip()
            if msg:
                broadcast(sock, msg)
    except (KeyboardInterrupt, EOFError):
        log("\nShutting down...")
        print_performance_report()
        sock.close()
        log("Server stopped.")


if __name__ == "__main__":
    main()

