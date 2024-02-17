#!/usr/bin/python3

#She's a mess 
import os
import re
import pyshark
import time
import socket
from outgoing_hash import * #outgoing_ARP_hash() and remove_ARP_hash()
import scapy.all import * #dunno if using yet
from getmac import get_mac_address as gma

class Packet:
    mac_addr;
    ip_addr;
    timestamp;

myMac = gma()
hostname = socket.gethostname()
myIp = socket.gethostbyname(hostname)


def capture_packets():
    arp_cache = {}
    hashtable = {} #?
    capture = pyshark.LiveCapture(interface='ethernet', bpf_filter='arp')
    #sniff for packets continuously
    #TODO: stop from adding to official ARP before we check it out. 
    for packet in capture.sniff_continuosly(timeout=None):
        #store packet data
        new_packet = Packet()
        new_packet.mac_addr = packet.eth._all_fields.values()
        new_packet.src_ip = packet.ip.src
        new_packet.dest_ip = packet.ip.dst
        new_packet.timestamp = packet.sniff_time
        
        if new_packet.src_ip == myIP: #outgoing
            #add to cache of outgoing requests without a response yet
            outgoing_ARP_hash(hashtable, new_packet)

        elif new_packet.dest_ip == myIP: #incoming
            if new_packet.mac_addr is in hashtable: 
                #maybe store based on mac_addr??
                #if is response to a sent arp request, remove from hash table
                remove_ARP_hash(hashtable, new_packet)
                if check_cache(arp_cache, new_packet.mac_addr) == False: 
                    #no duplicates ->> store the packet in our cache
                    store_cache(arp_cache, new_packet) 
                elif check_cache(arp_cache, new_packet.mac_addr) == True: 
                    #has duplicates -> TODO: handle

            elif new_packet.mac_addr not in hashtable:
                #is a gratuitous packet -> TODO: handle
                #may be bad guy \o-o/
    

def store_cache(arp_cache, new_packet):
"""I store Packet obj in our cache (dictionary)"""
    arp_cache[new_packet.mac_addr] = new_packet;
#dictionary (key, value) == (mac, Packet)


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



#Prevention:
#send junk packet, entrap them
#Getting a response when no request made
#use timestamps
#make as a daemon (fork child process and then exit parent)

