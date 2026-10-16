import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from scapy.all import raw, Ether, IP, TCP, rdpcap
from packetlab import manual, build, session, verify


def test_inet_checksum_known_vector():
    # RFC 1071 example bytes
    data = bytes.fromhex("0001f203f4f5f6f7")
    assert manual.inet_checksum(data) == 0x220d


def test_syn_fields_and_checksums():
    eth, ip, tcp, _ = build.build_layers()
    e, i, t = manual.parse_frame(raw(build.stack(eth, ip, tcp)))
    assert e.type == 0x0800 and i.proto == 6
    assert t.flag_names == ["SYN"]
    assert i.checksum_ok() and manual.tcp_checksum_ok(i, t)
    assert i.total_len == 40 and i.header_len == 20


def test_corrupted_byte_breaks_checksum():
    eth, ip, tcp, _ = build.build_layers(payload=b"hi")
    f = bytearray(raw(build.stack(eth, ip, tcp, b"hi")))
    f[-1] ^= 0xFF
    _, i, t = manual.parse_frame(bytes(f))
    assert not manual.tcp_checksum_ok(i, t)


def test_session_seq_ack_continuity(tmp_path):
    pk = session.http_session()
    assert len(pk) == 10
    syn, synack, ack = pk[0][TCP], pk[1][TCP], pk[2][TCP]
    assert synack.ack == syn.seq + 1 and ack.ack == synack.seq + 1
    req = pk[3]
    assert pk[4][TCP].ack == req[TCP].seq + len(req[TCP].payload)


def test_pcap_roundtrip_matches(tmp_path):
    p = str(tmp_path / "s.pcap")
    session.write(p)
    ok, rows = verify.check_pcap(p)
    assert ok and len(rows) == 10
