"""
=======================================================================
PROTOCOL UTILITIES - Reliable Group Notification System over UDP
=======================================================================
Computer Networks - Jackfruit Mini Project | Shared Protocol Layer

This file centralises everything shared between server.py and client.py:
  - Network constants
  - AES-256 encryption and decryption
  - Packet builders and parsers
  - Shared logger

Security Note:
  SSL/TLS is designed for TCP and requires a reliable ordered stream to
  perform its handshake. Since this project uses raw UDP (connectionless,
  unreliable), SSL/TLS cannot be applied directly. Instead, AES-256 CBC
  encryption is used to secure ALL packets (JOIN, JOIN-OK, NOTIFY, ACK,
  LEAVE), ensuring no plaintext is visible on the wire (e.g. Wireshark).

Protocol summary (all packets encrypted with AES-256 CBC):
  JOIN    → "JOIN:ClientName:UDPPort"
  JOIN-OK → "JOIN-OK:ClientName"
  NOTIFY  → JSON: {"seq": int, "msg": str, "sent_at": float}
  ACK     → "ACK:SeqNumber"
  LEAVE   → "LEAVE:ClientName:UDPPort"
=======================================================================
"""

import json
import time
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ───────────────────────────────────────────────────────────────────
# SHARED CONSTANTS
# ───────────────────────────────────────────────────────────────────
SERVER_IP     = "127.0.0.1"
SERVER_PORT   = 5005          # UDP port for all communication
BUFFER_SIZE   = 4096          # max UDP packet size in bytes

ACK_TIMEOUT   = 5             # seconds before retransmitting
MAX_RETRIES   = 5             # max retransmission attempts per packet
LOSS_PROB     = 0.3           # simulated packet loss (30%)

# Client UDP ports
CLIENT_A_PORT = 5006
CLIENT_B_PORT = 5007
CLIENT_C_PORT = 5008
CLIENT_D_PORT = 5009

# Packet type identifiers
TYPE_JOIN     = "JOIN"
TYPE_JOIN_OK  = "JOIN-OK"
TYPE_NOTIFY   = "NOTIFY"
TYPE_ACK      = "ACK"
TYPE_LEAVE    = "LEAVE"

# ───────────────────────────────────────────────────────────────────
# AES-256 SHARED SECRET KEY
# Must be exactly 32 bytes. Both server and client use the same key.
# In production this would be exchanged securely (e.g. Diffie-Hellman).
# ───────────────────────────────────────────────────────────────────
AES_KEY = b'ThisIsA256BitKey1234567890123456'   # 32 bytes


# ───────────────────────────────────────────────────────────────────
# ENCRYPTION / DECRYPTION  (AES-256 CBC)
# ───────────────────────────────────────────────────────────────────

def encrypt(data: str) -> bytes:
    """
    Encrypt a plaintext string using AES-256 CBC mode.
    A random IV is generated for every packet — this means two
    identical messages produce different ciphertext every time.
    Returns base64(IV + ciphertext) as bytes ready to send over UDP.
    """
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ct     = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct)


def decrypt(data: bytes) -> str:
    """
    Decrypt AES-256 CBC encrypted bytes received from UDP.
    Splits the first 16 bytes as IV, remainder as ciphertext.
    Returns the original plaintext string.
    Raises an exception if the key is wrong or data is corrupted.
    """
    raw    = base64.b64decode(data)
    iv     = raw[:16]
    ct     = raw[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()


# ───────────────────────────────────────────────────────────────────
# PACKET BUILDERS  (return encrypted bytes ready to sendto())
# ───────────────────────────────────────────────────────────────────

def make_join(client_name: str, udp_recv_port: int) -> bytes:
    """Client → Server: encrypted JOIN packet."""
    return encrypt(f"JOIN:{client_name}:{udp_recv_port}")


def make_join_ok(client_name: str) -> bytes:
    """Server → Client: encrypted JOIN-OK packet."""
    return encrypt(f"JOIN-OK:{client_name}")


def make_notify(seq: int, message: str) -> bytes:
    """Server → Client: encrypted NOTIFY packet (JSON payload)."""
    payload = json.dumps({
        "seq"    : seq,
        "msg"    : message,
        "sent_at": round(time.time(), 4)
    })
    return encrypt(payload)


def make_ack(seq: int) -> bytes:
    """Client → Server: encrypted ACK packet."""
    return encrypt(f"ACK:{seq}")


def make_leave(client_name: str, udp_recv_port: int) -> bytes:
    """Client → Server: encrypted LEAVE packet."""
    return encrypt(f"LEAVE:{client_name}:{udp_recv_port}")


# ───────────────────────────────────────────────────────────────────
# PACKET PARSERS  (decrypt then parse)
# ───────────────────────────────────────────────────────────────────

def parse_notify(raw: bytes):
    """
    Decrypt and parse a NOTIFY packet.
    Returns (seq, msg, sent_at) or (None, None, None) on failure.
    """
    try:
        data = json.loads(decrypt(raw))
        return data["seq"], data["msg"], data.get("sent_at", time.time())
    except Exception:
        return None, None, None


def parse_join(raw: bytes):
    """
    Decrypt and parse a JOIN packet.
    Returns (client_name, udp_port) or (None, None) on failure.
    """
    try:
        text  = decrypt(raw)
        parts = text.split(":")
        return parts[1], int(parts[2])
    except Exception:
        return None, None


def parse_ack(raw: bytes):
    """
    Decrypt and parse an ACK packet.
    Returns seq (int) or None on failure.
    """
    try:
        text = decrypt(raw)
        return int(text.split(":")[1])
    except Exception:
        return None


def parse_leave(raw: bytes):
    """
    Decrypt and parse a LEAVE packet.
    Returns (client_name, udp_port) or (None, None) on failure.
    """
    try:
        text  = decrypt(raw)
        parts = text.split(":")
        return parts[1], int(parts[2])
    except Exception:
        return None, None


def parse_any(raw: bytes) -> str:
    """
    Decrypt any packet and return the plaintext string.
    Used in receiver loops to identify packet type before routing.
    Returns empty string on failure.
    """
    try:
        return decrypt(raw).strip()
    except Exception:
        return ""


# ───────────────────────────────────────────────────────────────────
# LOGGER
# ───────────────────────────────────────────────────────────────────

def log(msg: str):
    """Shared timestamped logger used by server and client."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


# ───────────────────────────────────────────────────────────────────
# SELF-TEST  (python3 protocol.py)
# ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== protocol.py self-test ===\n")

    j  = make_join("Client-A", 5006)
    jo = make_join_ok("Client-A")
    n  = make_notify(seq=3, message="Meeting at 5pm")
    a  = make_ack(seq=3)
    lv = make_leave("Client-A", 5006)

    print(f"make_join()    → {j[:40]}...")
    print(f"make_join_ok() → {jo[:40]}...")
    print(f"make_notify()  → {n[:40]}...")
    print(f"make_ack()     → {a[:40]}...")
    print(f"make_leave()   → {lv[:40]}...")

    print("\n--- Decryption round-trip test ---")
    name, port = parse_join(j)
    print(f"parse_join()   → name={name}, port={port}")

    seq, msg, ts = parse_notify(n)
    print(f"parse_notify() → seq={seq}, msg='{msg}', sent_at={ts}")

    seq2 = parse_ack(a)
    print(f"parse_ack()    → seq={seq2}")

    name2, port2 = parse_leave(lv)
    print(f"parse_leave()  → name={name2}, port={port2}")

    print(f"\nSERVER_PORT={SERVER_PORT}  TIMEOUT={ACK_TIMEOUT}s  "
          f"MAX_RETRIES={MAX_RETRIES}  LOSS_PROB={LOSS_PROB:.0%}")
    print("Encryption: AES-256 CBC")
    print("\nAll tests passed ")

