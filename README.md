# packet-anatomy-scapy

Build an Ethernet → IPv4 → TCP packet **layer by layer** with [Scapy](https://github.com/secdev/scapy),
print every header field with byte offsets, and **prove** the result is correct with an independent,
hand-written parser that recomputes the IP and TCP checksums from scratch.

Mini-project for *21CSC302J – Computer Networks* (Units 1 & 2), SRM Institute of Science and Technology.

## What it does

| Command | What happens |
|---|---|
| `python main.py anatomy` | Stacks `Ether()/IP()/TCP()` one layer at a time, prints each header (raw hex + decoded fields + byte range), saves `captures/single_syn.pcap` |
| `python main.py session` | Crafts a full TCP conversation (3-way handshake → HTTP GET/200 → FIN teardown), 10 packets, saves `captures/http_session.pcap` |
| `python main.py verify [pcap]` | Re-reads a pcap and cross-checks every packet: Scapy's fields vs. my `struct`-based parser, plus IP/TCP checksum validation |
| `pytest` | 5 tests (RFC 1071 checksum vector, field/checksum checks, corruption detection, seq/ack continuity, pcap round-trip) |

## Project layout

```
packetlab/manual.py    Scapy-free parser (struct) + RFC 1071 checksum + TCP pseudo-header checksum
packetlab/build.py     Layer-by-layer builder and annotated header printer
packetlab/session.py   Handshake / data / teardown generator with correct seq/ack bookkeeping
packetlab/verify.py    Scapy-vs-manual cross-check over a pcap
main.py                CLI
tests/                 pytest suite
captures/              Generated .pcap files (open in Wireshark)
docs/                  Saved program output
```

## Run it

```bash
pip install -r requirements.txt
python main.py anatomy
python main.py session
python main.py verify
pytest
```
No root needed: packets are written to pcap files, not sent on the wire.

## Sample output

Excerpt of `python main.py anatomy` (full text in `docs/anatomy_output.txt`):

```
[Layer 3] IPv4  (bytes 14-33)
  raw      : 45 00 00 28 12 34 40 00 40 06 14 9a 0a 00 00 01 0a 00 00 02
  version  : 4   IHL: 5 (20 bytes)
  total length: 40   id: 0x1234   flags: 010 (DF=1)   ttl: 64   protocol: 6 (TCP)
  checksum : 0x149a   valid: True
[Layer 4] TCP  (bytes 34-53)
  ports    : 43210 -> 80   seq: 1000   ack: 0   flags: 0x02 ['SYN']
  checksum : 0xf3ec   valid (pseudo-header): True
```

`python main.py verify`:

```
 # flags       seq    ack  len  result
 1 SYN        1000      0    0  OK
 2 SYN+ACK    5000   1001    0  OK
 3 ACK        1001   5001    0  OK
 4 PSH+ACK    1001   5001   34  OK
 ...
10 ACK        1036   5055    0  OK
ALL PACKETS MATCH
```

## Matching with Wireshark

Open `captures/http_session.pcap` in Wireshark (File → Open) and compare against the printed output:

1. Select packet 1 and expand *Ethernet II*, *Internet Protocol*, *Transmission Control Protocol*. Fields (ports, seq=1000, flags=SYN, header checksum 0x149a for the single SYN capture) should match.
2. Wireshark may show the checksum as "unverified"/"incorrect" only if checksum validation is toggled differently in *Preferences → Protocols*; here they are correct by construction.
3. Use *Statistics → Flow Graph* (TCP flows) to see the handshake and teardown.

_Screenshots: add yours to `docs/` (e.g. `docs/wireshark_syn.png`, `docs/wireshark_flow.png`) and link them here._

## What I learned

- **Layering is just concatenation**: each header carries a "what comes next" field (EtherType 0x0800 → IPv4, protocol 6 → TCP) and a length, which is how a receiver peels layers off.
- **Checksums**: the IP checksum covers only the IP header; the TCP checksum also covers a *pseudo-header* (src/dst IP, protocol, length) plus payload. A single flipped payload byte breaks it (tested).
- **TCP bookkeeping**: SYN and FIN each consume one sequence number; an ACK number is always "next byte I expect" = peer's seq + payload length. The generated session follows this exactly.
- **Why independent verification matters**: a second parser written straight from the RFC header diagrams gives real confidence that Scapy's output (and the pcap) is correct, instead of trusting one library to check itself.

## Possible extensions

- Send the packets on a veth/tap interface and capture live.
- Add UDP, ICMP and ARP layers, or fragment a large IP packet and reassemble it.
- Detect anomalies (bad checksums, out-of-order seq) in arbitrary pcaps.
