"""Build a packet one layer at a time with Scapy and annotate every header."""
from __future__ import annotations
from scapy.all import Ether, IP, TCP, Raw, raw

from . import manual


def hexdump(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def build_layers(src_mac="02:00:00:00:00:01", dst_mac="02:00:00:00:00:02",
                 src_ip="10.0.0.1", dst_ip="10.0.0.2",
                 sport=43210, dport=80, flags="S", seq=1000, ack=0, payload=b""):
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip, ttl=64, id=0x1234, flags="DF")
    tcp = TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=64240)
    return eth, ip, tcp, payload


def stack(eth, ip, tcp, payload=b""):
    pkt = eth / ip / tcp
    return pkt / Raw(payload) if payload else pkt


def explain(pkt) -> str:
    """Return a field-by-field breakdown with byte offsets (Wireshark-style)."""
    frame = raw(pkt)               # Scapy fills in lengths + checksums here
    eth, ip, tcp = manual.parse_frame(frame)
    out = []
    p = 0
    out.append(f"Frame length: {len(frame)} bytes")
    out.append(f"\n[Layer 2] Ethernet II  (bytes {p}-{p+13})")
    out.append(f"  raw      : {hexdump(frame[:14])}")
    out.append(f"  dst MAC  : {eth.dst}")
    out.append(f"  src MAC  : {eth.src}")
    out.append(f"  ethertype: 0x{eth.type:04x} (IPv4)")
    p = 14
    out.append(f"\n[Layer 3] IPv4  (bytes {p}-{p+ip.header_len-1})")
    out.append(f"  raw      : {hexdump(frame[p:p+ip.header_len])}")
    out.append(f"  version  : {ip.version}   IHL: {ip.ihl} ({ip.header_len} bytes)")
    out.append(f"  tos      : 0x{ip.tos:02x}   total length: {ip.total_len}")
    out.append(f"  id       : 0x{ip.ident:04x}   flags: {ip.flags:03b} (DF={ip.flags>>1 & 1})   frag offset: {ip.frag_off}")
    out.append(f"  ttl      : {ip.ttl}   protocol: {ip.proto} (TCP)")
    out.append(f"  checksum : 0x{ip.checksum:04x}   valid: {ip.checksum_ok()}")
    out.append(f"  src -> dst: {ip.src} -> {ip.dst}")
    p += ip.header_len
    out.append(f"\n[Layer 4] TCP  (bytes {p}-{p+tcp.data_off*4-1})")
    out.append(f"  raw      : {hexdump(frame[p:p+tcp.data_off*4])}")
    out.append(f"  ports    : {tcp.sport} -> {tcp.dport}")
    out.append(f"  seq      : {tcp.seq}   ack: {tcp.ack}")
    out.append(f"  data off : {tcp.data_off} ({tcp.data_off*4} bytes)   flags: 0x{tcp.flags:02x} {tcp.flag_names}")
    out.append(f"  window   : {tcp.window}   urgent: {tcp.urgent}")
    out.append(f"  checksum : 0x{tcp.checksum:04x}   valid (pseudo-header): {manual.tcp_checksum_ok(ip, tcp)}")
    if tcp.payload:
        out.append(f"\n[Payload] {len(tcp.payload)} bytes: {tcp.payload!r}")
    return "\n".join(out)
