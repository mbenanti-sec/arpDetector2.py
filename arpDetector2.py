#!/usr/bin/env python3
from scapy.all import sniff, ARP, Ether

IP_MAC_Map = {}

def processPacket(packet):
    if not packet.haslayer(ARP):
        return

    src_IP = packet[ARP].psrc
    src_MAC = packet[Ether].src

    old_IP = IP_MAC_Map.get(src_MAC)

    if old_IP is None:
        IP_MAC_Map[src_MAC] = src_IP
        return

    if old_IP != src_IP:
        
        message = (
            "\n*** Possible ARP attack detected ***\n"
            f"MAC: {src_MAC}\n"
            f"Known IP: {old_IP}\n"
            f"Now claims IP: {src_IP}\n"
        )
        print(message)
        IP_MAC_Map[src_MAC] = src_IP

if __name__ == "__main__":
    sniff(filter="arp", store=0, prn=processPacket)
