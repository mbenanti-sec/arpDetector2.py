# arpDetector2.py
A simple ARP spoofing detector that listens to ARP traffic and alerts when a MAC address starts claiming a different IP address than before, which may indicate an ARP poisoning attack.

# arpDetector2

A simple ARP spoofing detector written in Python using `scapy`.  
The script passively listens for ARP packets on the network and keeps track of
the IP address associated with each MAC address. If a MAC address suddenly
claims a different IP than the one previously seen, it raises an alert for a
possible ARP poisoning attack.

> ⚠️ For educational and lab use only. Run this script only on networks you are authorized to monitor.

## Features

- Listens to ARP packets in real time
- Maintains an in-memory IP→MAC mapping
- Prints a warning when a MAC address starts claiming a new IP

## Requirements

- Python 3
- `scapy` Python library
- Root/administrator privileges (required for packet sniffing)

Install `scapy` (example):

```bash
pip install scapy

