#!/usr/bin/python3

import os
import re
import pyshark
import time

class Packet:
    mac_addr;
    ip_addr;
    timestamp;

arp_cache = {}
capture = pyshark.LiveCapture('ethernet') #or whatever

#sniff for packets continuously
for packet in capture.sniff_continuosly(timeout=None): #or packet_count=x
    #store packet data
    new_packet = Packet()
    new_packet.mac_addr = packet.eth._all_fields.values()
    new_packet.ip_addr = packet.eth.src #or packet.ip.src
    new_packet.timestamp = time.time()
    

    #check for duplicate MAC addresses
    if (check_cache(arp_cache, new_packet.mac_addr) == False): #no duplicates
        #store the packet in our cache
        store_cache(arp_cache, new_packet) 
    else if (check_cache(new_packet.mac_addr) == True): # has duplicates
        #check other ip_addr with this mac
        other_packet = get_cache(arp_cache, mac_addr)  
        if other_packet.timestamp > new_packet.timestamp:
            #one of them is the bad guy
    

def daemon():
    pid = os.fork()
    if pid > 0:
        sys.exit("yay")
    elif:
        sys.exit("bad")

def store_cache(arp_cache, new_packet):
"""I store Packet obj in our cache (dictionary)"""
    arp_cache[new_packet.mac_addr] = new_packet;
#dictionary (key, value) (mac, Packet)


def check_cache(arp_cache, mac_addr):
"""I check the cache for duplicate mac addresses. I return a bool"""
    for el in arp_cache:
        if mac_addr == el:
            return True
    return False

def get_cache(arp_cache, mac_addr):
    """I take a mac address and return a Packet obj"""
    packet = arp_cache[mac_addr]
    return packet


#TODO:

#Prevention:
#send junk packet, entrap them
#Getting a response when no request made
#use timestamps
#make as a daemon (fork child process and then exit parent)

