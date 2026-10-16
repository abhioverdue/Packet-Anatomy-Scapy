"""Cross-check a pcap: Scapy's dissection vs. the hand-written parser."""
from __future__ import annotations
from scapy.all import rdpcap, raw, IP, TCP
from . import manual


def check_pcap(path: str):
    rows, ok = [], True
    for i, pkt in enumerate(rdpcap(path), 1):
        frame = raw(pkt)
        eth, ip, tcp = manual.parse_frame(frame)
        s_ip, s_tcp = pkt[IP], pkt[TCP]
        checks = {
            "ip.src/dst": (ip.src, ip.dst) == (s_ip.src, s_ip.dst),
            "ip.csum": ip.checksum_ok() and ip.checksum == s_ip.chksum,
            "tcp.ports": (tcp.sport, tcp.dport) == (s_tcp.sport, s_tcp.dport),
            "tcp.seq/ack": (tcp.seq, tcp.ack) == (s_tcp.seq, s_tcp.ack),
            "tcp.flags": tcp.flags == int(s_tcp.flags),
            "tcp.csum": manual.tcp_checksum_ok(ip, tcp) and tcp.checksum == s_tcp.chksum,
        }
        ok &= all(checks.values())
        rows.append((i, "+".join(tcp.flag_names), tcp.seq, tcp.ack,
                     len(tcp.payload), checks))
    return ok, rows


def report(path: str) -> bool:
    ok, rows = check_pcap(path)
    print(f"{'#':>2} {'flags':<8} {'seq':>6} {'ack':>6} {'len':>4}  result")
    for i, fl, seq, ack, ln, checks in rows:
        bad = [k for k, v in checks.items() if not v]
        print(f"{i:>2} {fl:<8} {seq:>6} {ack:>6} {ln:>4}  {'OK' if not bad else 'MISMATCH: ' + ','.join(bad)}")
    print("\nALL PACKETS MATCH" if ok else "\nMISMATCHES FOUND")
    return ok
