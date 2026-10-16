"""CLI:  python main.py anatomy | session | verify [pcap]"""
import sys
from scapy.all import wrpcap
from packetlab import build, session, verify


def anatomy():
    eth, ip, tcp, payload = build.build_layers(flags="S")
    print("=== Building layer by layer ===")
    pkt = eth
    print(f"\n>>> Ether(): {eth.summary()}")
    pkt = pkt / ip
    print(f">>> + IP():   {pkt.summary()}")
    pkt = pkt / tcp
    print(f">>> + TCP():  {pkt.summary()}\n")
    print(build.explain(pkt))
    wrpcap("captures/single_syn.pcap", pkt)
    print("\nSaved captures/single_syn.pcap (open in Wireshark to compare)")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "anatomy"
    if cmd == "anatomy":
        anatomy()
    elif cmd == "session":
        pk = session.write()
        for i, p in enumerate(pk, 1):
            print(f"{i:>2}  {p.summary()}")
        print("\nSaved captures/http_session.pcap")
    elif cmd == "verify":
        sys.exit(0 if verify.report(sys.argv[2] if len(sys.argv) > 2
                                    else "captures/http_session.pcap") else 1)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
