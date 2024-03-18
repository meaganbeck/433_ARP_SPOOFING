#!/usr/bin/python3

import subprocess



def store_cache(arp_cache, packet):
    """Cache an (ip,mac) pairing."""
    arp_cache[packet.src_ip] = packet.src_mac
    #dictionary (key, value) == (ip, mac)

def check_cache(arp_cache, packet):
    """Check if the declared (ip, mac) pair mapping is cached. """
    return (arp_cache[packet.src_ip] == packet.src_mac)

def remove_cache(arp_cache, packet):
    """Purge cache entries associated with a packet's source IP."""
    del arp_cache[packet.src_ip]
    subprocess.run(["arp", "-d", f"{packet.src_ip}"])

