#!/usr/bin/python3

import os
import re
import pyshark
import time
import socket
from sys import argv
from outgoing_hash import * #outgoing_ARP_hash(), remove_ARP_hash(), check_hash()
from arp_cache import * #store_cache(), check_cache(), get_cache()
from scapy.all import *
from handle_packets import * #block_cache(), block_gratuitous()

# argv contains: interface name, interface ip, interface mac, host name (in that order)
my_name = argv[0]
my_IP = argv[1]
my_MAC = argv[2]
host_name = argv[3]


class Packet:
    mac_addr;
    ip_addr;
    timestamp;


def capture_packets():
    block_gratuitous(my_name) #drops all gratuitous responses
    block_arp_cache(my_name) #blocks all arp responses, does not store in cache
    
    arp_cache = {}
    hashtable = {} #?
    
    capture = pyshark.LiveCapture(interface=my_name, bpf_filter='arp')
    
    #sniff for packets continuously
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
            if check_hash(new_packet.mac_addr) == True: 
                #is response to a sent arp request-> remove from hash table
                remove_ARP_hash(hashtable, new_packet)
                
                if check_cache(arp_cache, new_packet.mac_addr) == False: 
                    #no duplicates -> store the packet in our cache
                    store_cache(arp_cache, new_packet) 
                
                    #manually send a response
                    create_arp_reply(new_packet)
                
                elif check_cache(arp_cache, new_packet.mac_addr) == True: 
                    #has duplicates -> TODO: handle
                    
                    #remove from cache and drop new packet
                    remove_cache(arp_cache, new_packet.mac_addr)

            elif check_hash(new_packet.mac_addr) == False:
   
                #may be bad guy \o-o/
    
def create_arp_reply(new_packet)
    sendp(Ether(dst=new_packet.mac_addr)/ARP(hwdst=new_packet.mac_addr, pdst=new_packet.dest_ip, psrc=new_packet.src_ip), my_name)




#Prevention:
#send junk packet, entrap them
#use timestamps
#TODO: "ethernet" fix name -> interface (use argv entries)
