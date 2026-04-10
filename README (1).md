# Reliable Group Notification System over UDP

**Computer Networks — Jackfruit Mini Project**

A UDP-based group notification system that reliably delivers messages to multiple clients using sequence numbers, acknowledgements, retransmission, and AES-256 encryption — all implemented at the application layer without any high-level frameworks.

---

## Project overview

This project implements a one-to-many notification system where a server broadcasts messages to all registered clients over UDP. Since UDP is inherently unreliable, reliability is built manually using:

- Sequence numbers to detect loss and ordering issues
- ACK-based retransmission with a 5-second timeout
- Duplicate packet detection using seen sequence tracking
- Simulated 30% packet loss to demonstrate and test the retry mechanism
- AES-256 CBC encryption on every packet sent over the wire

### Security note

SSL/TLS is designed for TCP and requires a reliable, ordered stream to complete its handshake. Since this project uses raw UDP (connectionless and unreliable), SSL/TLS cannot be applied directly. Instead, AES-256 CBC symmetric encryption is used to secure all packets — JOIN, JOIN-OK, NOTIFY, ACK, and LEAVE — ensuring no plaintext is visible on the network (verified via Wireshark).

---

## File structure

```
CN_FINAL/
├── protocol.py    # Shared layer: AES-256 encryption, packet builders, parsers, constants
├── server.py      # Server: broadcast engine, ACK tracker, retransmission logic
├── client.py      # Client: receive, decrypt, ACK, performance stats
└── README.md      # This file
```

### What each file does

**`protocol.py`** — the single source of truth for the entire protocol. Contains the AES-256 key and all encrypt/decrypt functions, packet builder functions (`make_join`, `make_notify`, `make_ack`, etc.), packet parser functions (`parse_join`, `parse_notify`, `parse_ack`, etc.), shared constants (`SERVER_PORT`, `ACK_TIMEOUT`, `MAX_RETRIES`, `LOSS_PROB`), and the shared logger. Neither server nor client define their own encryption — they import everything from here.

**`server.py`** — listens on UDP port 5005. Handles encrypted JOIN and LEAVE packets to maintain a live client registry. When a message is typed, it encrypts and broadcasts to all registered clients simultaneously using `make_notify()`. Tracks pending ACKs per client per sequence number and retransmits up to 5 times if no ACK arrives within 5 seconds. Removes unresponsive clients after max retries. Prints a full performance report on shutdown.

**`client.py`** — binds to its assigned UDP port (5006, 5007, or 5008). Sends an encrypted JOIN to register with the server. Runs a background thread that receives, decrypts, and processes incoming NOTIFY packets. Simulates 30% random packet loss to trigger server retransmission. Tracks sequence numbers to detect duplicates and out-of-order delivery. Sends encrypted ACK for every successfully received packet. Sends encrypted LEAVE on Ctrl+C and prints a performance report.

---

## Architecture

```
                      SERVER (port 5005)
                   Broadcast · Retry · ACK
                           |
                    protocol.py
               AES-256 · Builders · Parsers
                    /         |         \
             NOTIFY        NOTIFY      NOTIFY   ← encrypted UDP
                /             |             \
         Client-A        Client-B        Client-C
          (5006)          (5007)          (5008)
             \               |              /
              ACK           ACK           ACK    ← encrypted UDP (dashed)
```

All arrows in both directions carry AES-256 encrypted UDP packets. No plaintext is ever sent on the wire.

---

## Protocol

All packets are encrypted with AES-256 CBC before being placed in a UDP datagram. The plaintext formats are:

| Packet   | Direction        | Plaintext format                          |
|----------|-----------------|-------------------------------------------|
| JOIN     | Client → Server | `JOIN:ClientName:UDPPort`                 |
| JOIN-OK  | Server → Client | `JOIN-OK:ClientName`                      |
| NOTIFY   | Server → Client | `{"seq": int, "msg": str, "sent_at": float}` |
| ACK      | Client → Server | `ACK:SeqNumber`                           |
| LEAVE    | Client → Server | `LEAVE:ClientName:UDPPort`                |

---

## Setup and installation

### Prerequisites

- Python 3.8 or higher
- Ubuntu / Linux (tested on Ubuntu 24)

### Install dependency

```bash
pip install pycryptodome --break-system-packages
```

### Verify installation

```bash
python3 -c "from Crypto.Cipher import AES; print('pycryptodome OK')"
```

---

## How to run

### Step 1 — verify protocol (optional but recommended)

```bash
python3 protocol.py
```

Expected output:
```
=== protocol.py self-test ===
make_join()    → b'2DX6JU4K6GH9...'
...
All tests passed ✓
```

### Step 2 — start the server (Terminal 1)

```bash
python3 server.py
```

Wait until you see:
```
[HH:MM:SS] Listening on port : 5005
[HH:MM:SS] Encryption        : AES-256 CBC (all packets)
```

### Step 3 — connect clients (Terminals 2, 3, 4)

```bash
python3 client.py 5006 Client-A
python3 client.py 5007 Client-B
python3 client.py 5008 Client-C
```

Each client prints `Server: JOIN-OK:Client-X` when registered.

### Step 4 — broadcast a message

In Terminal 1, type any message and press Enter:

```
Notification> hello everyone
```

All connected clients receive, decrypt, and display the notification.

### Step 5 — stop

Press `Ctrl+C` in any client terminal to disconnect gracefully. The client sends an encrypted LEAVE and prints its performance report. Press `Ctrl+C` in the server terminal to shut down and print the server performance report.

---

## Features demonstrated

### Reliable delivery
Every NOTIFY packet carries a sequence number. The server starts a 5-second retransmission timer per packet per client. If no ACK arrives, the packet is retransmitted. This repeats up to 5 times before the client is removed as unresponsive.

### Simulated packet loss
Clients randomly drop 30% of incoming packets without sending an ACK. This triggers server retransmission and demonstrates the reliability mechanism. The 5-second latency visible on retransmitted packets (e.g. `Latency: 5007.66 ms`) is the retransmit timeout in action.

### Duplicate detection
If a retransmitted packet arrives after the original was already processed (because the ACK was lost), the client detects the duplicate via its `seen_seqs` set and sends an ACK without processing the message twice.

### Out-of-order detection
If a client joins late and misses earlier sequence numbers, it logs a warning and adjusts its expected sequence counter. This does not prevent delivery of the received packet.

### AES-256 encryption
Every byte on the wire is encrypted. Wireshark captures show only base64-encoded ciphertext — no message content, no client names, no sequence numbers are readable without the shared key.

---

## Performance report (sample)

### Server
```
SESSION DURATION        : 92.4 seconds
TOTAL BROADCASTS        : 2
TOTAL PACKETS SENT      : 5
RETRANSMISSIONS         : 1
ACKS RECEIVED           : 5
CLIENTS JOINED          : 3
CLIENTS LEFT            : 0
```

### Client
```
CLIENT NAME             : Client-C
UDP PORT                : 5008
ENCRYPTION              : AES-256 CBC
TOTAL PACKETS ARRIVED   : 2
PACKETS DROPPED (SIM)   : 1
ACKS SENT               : 2
AVG LATENCY             : 2504.17 ms
DELIVERY SUCCESS RATE   : 50.0%
```

---

## Rubric coverage

| Component | Coverage |
|-----------|---------|
| Problem definition and architecture | UDP group notification, reliable delivery, AES-256 security |
| Core implementation | Raw UDP sockets, no frameworks, manual socket binding |
| Feature implementation | Retransmission, sequence numbers, ACK tracking, encryption |
| Performance evaluation | Latency, loss rate, delivery success rate tracked per client |
| Optimisation and fixes | Thread-safe locks, LEAVE handling, max retry removal, edge cases |
| GitHub and demo | This README, documented code, live demo with Wireshark proof |

---

## Authors
BR MANAVI-PES2UG24CS105
ANVII RAI.S-PES2UG24CS076
ATHARVA SINGH-PES2UG24CS095

Computer Networks — Jackfruit Mini Project  
Language: Python 3  
Encryption: AES-256 CBC (pycryptodome)  
Transport: Raw UDP sockets
