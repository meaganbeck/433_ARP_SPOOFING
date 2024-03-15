#!/usr/bin/python3

import os
import re
# import pyshark
import time
import socket

#TODO: 
#Build cache; use a Class? 


def store_cache(arp_cache, new_packet):
    """I store Packet obj in our cache (dictionary)"""
    arp_cache[new_packet.mac_addr] = new_packet;
#dictionary (key, value) == (mac, Packet)


def check_cache(arp_cache, mac_addr):
    #TODO: rewrite 
    """I check the cache for duplicate mac addresses. I return a bool"""
    for el in arp_cache:
        if mac_addr == el:
            return True
    return False

def get_cache(arp_cache, mac_addr):
    """I take a mac address and return a Packet obj"""
    packet = arp_cache[mac_addr]
    return packet

def remove_cache(arp_cache, mac_addr):
    """I take a mac address and remove all entries with the address from the cache"""
    del arp_cache[mac_addr]
