"""Independent, Scapy-free parser for Ethernet / IPv4 / TCP.

Written with `struct` straight from the RFC 791 / RFC 9293 header diagrams so it
can be used to cross-check what Scapy builds (and what Wireshark will show).
"""
from __future__ import annotations
import socket
import struct
from dataclasses import dataclass

TCP_FLAGS = [("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08),
             ("ACK", 0x10), ("URG", 0x20), ("ECE", 0x40), ("CWR", 0x80)]


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def inet_checksum(data: bytes) -> int:
    """RFC 1071 ones'-complement 16-bit checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


@dataclass
class Ether:
    dst: str; src: str; type: int
    LEN = 14


@dataclass
class IPv4:
    version: int; ihl: int; tos: int; total_len: int; ident: int
    flags: int; frag_off: int; ttl: int; proto: int; checksum: int
    src: str; dst: str; header_bytes: bytes

    @property
    def header_len(self) -> int:
        return self.ihl * 4

    def checksum_ok(self) -> bool:
        # checksum over a header that includes its own checksum must be 0
        return inet_checksum(self.header_bytes) == 0


@dataclass
class TCP:
    sport: int; dport: int; seq: int; ack: int; data_off: int
    flags: int; window: int; checksum: int; urgent: int
    options: bytes; payload: bytes; segment_bytes: bytes

    @property
    def flag_names(self) -> list[str]:
        return [n for n, bit in TCP_FLAGS if self.flags & bit]


def parse_ether(raw: bytes) -> Ether:
    dst, src, t = struct.unpack("!6s6sH", raw[:14])
    return Ether(mac_str(dst), mac_str(src), t)


def parse_ipv4(raw: bytes) -> IPv4:
    (vihl, tos, tlen, ident, ff, ttl, proto, csum, src, dst) = struct.unpack(
        "!BBHHHBBH4s4s", raw[:20])
    ihl = vihl & 0x0F
    return IPv4(vihl >> 4, ihl, tos, tlen, ident, ff >> 13, ff & 0x1FFF, ttl,
                proto, csum, socket.inet_ntoa(src), socket.inet_ntoa(dst),
                raw[: ihl * 4])


def parse_tcp(raw: bytes) -> TCP:
    (sp, dp, seq, ack, off_res, flags, win, csum, urg) = struct.unpack(
        "!HHIIBBHHH", raw[:20])
    off = off_res >> 4
    return TCP(sp, dp, seq, ack, off, flags, win, csum, urg,
               raw[20: off * 4], raw[off * 4:], raw)


def tcp_checksum(ip: IPv4, seg: bytes) -> int:
    """TCP checksum incl. the IPv4 pseudo-header, computed from scratch."""
    pseudo = (socket.inet_aton(ip.src) + socket.inet_aton(ip.dst)
              + struct.pack("!BBH", 0, 6, len(seg)))
    return inet_checksum(pseudo + seg)


def parse_frame(frame: bytes):
    eth = parse_ether(frame)
    if eth.type != 0x0800:
        return eth, None, None
    ip = parse_ipv4(frame[14:])
    if ip.proto != 6:
        return eth, ip, None
    tcp = parse_tcp(frame[14 + ip.header_len: 14 + ip.total_len])
    return eth, ip, tcp


def tcp_checksum_ok(ip: IPv4, tcp: TCP) -> bool:
    return tcp_checksum(ip, tcp.segment_bytes) == 0
