"""Craft a complete TCP conversation (handshake, request/response, teardown)."""
from __future__ import annotations
from scapy.all import Ether, IP, TCP, Raw, wrpcap

C_MAC, S_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
C_IP, S_IP = "10.0.0.1", "10.0.0.2"
C_PORT, S_PORT = 43210, 80
MSS_OPTS = [("MSS", 1460), ("NOP", None), ("WScale", 7), ("SAckOK", b"")]


def _p(frm_client: bool, flags: str, seq: int, ack: int, payload=b"", opts=None):
    a = (C_MAC, C_IP, C_PORT, S_MAC, S_IP, S_PORT) if frm_client else \
        (S_MAC, S_IP, S_PORT, C_MAC, C_IP, C_PORT)
    pkt = (Ether(src=a[0], dst=a[3]) / IP(src=a[1], dst=a[4], flags="DF")
           / TCP(sport=a[2], dport=a[5], flags=flags, seq=seq, ack=ack,
                 window=64240, options=opts or []))
    return pkt / Raw(payload) if payload else pkt


def http_session(c_isn=1000, s_isn=5000):
    req = b"GET / HTTP/1.1\r\nHost: 10.0.0.2\r\n\r\n"
    body = b"<h1>hello</h1>"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body)) + body
    c, s = c_isn, s_isn
    pk = []
    pk.append(_p(True,  "S",  c, 0, opts=MSS_OPTS));              c += 1          # SYN
    pk.append(_p(False, "SA", s, c, opts=MSS_OPTS));              s += 1          # SYN-ACK
    pk.append(_p(True,  "A",  c, s))                                              # ACK
    pk.append(_p(True,  "PA", c, s, req));                        c += len(req)   # request
    pk.append(_p(False, "A",  s, c))                                              # ACK
    pk.append(_p(False, "PA", s, c, resp));                       s += len(resp)  # response
    pk.append(_p(True,  "A",  c, s))                                              # ACK
    pk.append(_p(True,  "FA", c, s));                             c += 1          # FIN
    pk.append(_p(False, "FA", s, c));                             s += 1          # FIN
    pk.append(_p(True,  "A",  c, s))                                              # last ACK
    return pk


def write(path="captures/http_session.pcap"):
    pk = http_session()
    wrpcap(path, pk)
    return pk
