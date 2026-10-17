import argparse
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNSQR, Raw

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
captured = []
count = 0


def show_payload(packet):
    if packet.haslayer(Raw):
        data = bytes(packet[Raw].load)[:60]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        print(f"  Payload ({len(packet[Raw].load)} bytes): {text}")
    else:
        print("  Payload: none")


def process_packet(packet):
    global count
    count += 1
    captured.append(packet)
    now = datetime.now().strftime("%H:%M:%S")
    print(f"\n[{count}] {now}  ({len(packet)} bytes)")

    if packet.haslayer(ARP):
        arp = packet[ARP]
        kind = "Request" if arp.op == 1 else "Reply"
        print(f"  Protocol: ARP {kind}")
        print(f"  {arp.psrc} ({arp.hwsrc}) -> {arp.pdst} ({arp.hwdst})")
        return

    if packet.haslayer(IP):
        ip = packet[IP]
        src, dst = ip.src, ip.dst
        proto = PROTOCOLS.get(ip.proto, f"Other({ip.proto})")
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        src, dst = ip.src, ip.dst
        proto = f"IPv6 (next header {ip.nh})"
    else:
        print("  Non-IP packet")
        return

    print(f"  Source IP:      {src}")
    print(f"  Destination IP: {dst}")
    print(f"  Protocol:       {proto}")

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print(f"  Ports:          {tcp.sport} -> {tcp.dport}")
        print(f"  TCP Flags:      {tcp.flags}")
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"  Ports:          {udp.sport} -> {udp.dport}")
    elif packet.haslayer(ICMP):
        print(f"  ICMP Type:      {packet[ICMP].type}")

    if packet.haslayer(DNSQR):
        print(f"  DNS Query:      {packet[DNSQR].qname.decode(errors='ignore')}")

    show_payload(packet)


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer")
    parser.add_argument("-c", "--count", type=int, default=20, help="packets to capture")
    parser.add_argument("-i", "--iface", default=None, help="network interface")
    parser.add_argument("-f", "--filter", default=None, help='BPF filter, e.g. "tcp port 80"')
    parser.add_argument("-w", "--write", default=None, help="save to .pcap file")
    args = parser.parse_args()

    print("Sniffing started... (Ctrl+C to stop)")
    try:
        sniff(iface=args.iface, filter=args.filter, prn=process_packet,
              count=args.count, store=False)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except PermissionError:
        print("Permission denied. Run with sudo.")
        return

    print(f"\nDone. Captured {count} packets.")
    if args.write and captured:
        wrpcap(args.write, captured)
        print(f"Saved to {args.write}")


if __name__ == "__main__":
    main()
