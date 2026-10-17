# Network-Sniffer
A basic python based project to capture network traffic packets
# Basic Network Sniffer

A Python program that captures live network packets and displays their key details. It was built to understand packet structure, protocols and how data flows through a network.

## Features
- Captures packets using the Scapy library
- Shows time, source/destination IP, protocol, ports and TCP flags
- Decodes ARP, ICMP, TCP, UDP, IPv6 and DNS queries
- Displays a readable payload preview
- Supports interface selection, BPF filters, packet count and saving to a .pcap file

## Requirements
- Ubuntu/Linux, Python 3, Scapy (`sudo apt install python3-scapy`)
- Root privileges (sudo)

## Usage
    sudo python3 sniffer.py -i wlp0s20f3
    sudo python3 sniffer.py -i wlp0s20f3 -f "tcp port 80" -c 10
    sudo python3 sniffer.py -i wlp0s20f3 -c 50 -w capture.pcap

## Options
| Option | Meaning |
|---|---|
| -i | Network interface |
| -c | Number of packets to capture (default 20) |
| -f | BPF filter, e.g. "udp port 53" |
| -w | Save capture to a .pcap file |

## Findings
- HTTP (port 80) payloads are readable text, which shows why HTTP is insecure.
- HTTPS and QUIC (port 443) payloads are encrypted and unreadable.

## Note
Use only on networks you own or have permission to monitor.
EOF
