#!/usr/bin/python3

#She's a mess 
import os
import re
import pyshark
import time
import socket
from outgoing_hash import * #outgoing_ARP_hash(), remove_ARP_hash(), check_hash()
from arp_cache import * #store_cache(), check_cache(), get_cache()
import scapy.all import * #dunno if using yet
from handle_packets import * #block_cache(), block_gratuitous()
from getmac import get_mac_address as gma

myMac = gma()
hostname = socket.gethostname()
myIp = socket.gethostbyname(hostname)

class Packet:
    mac_addr;
    ip_addr;
    timestamp;

def capture_packets():
    block_gratuitous() #drops all gratuitous responses
    block_arp_cache() #blocks all arp responses, does not store in cache
    
    arp_cache = {}
    hashtable = {} #?
    
    capture = pyshark.LiveCapture(interface='ethernet', bpf_filter='arp')
    
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

            elif check_hash(new_packet.mac_addr) == False:
                block_gratuitous() 
                #may be bad guy \o-o/
    
def create_arp_reply(new_packet)
    #src = other guy
    #dest_ip = mine
    #mac_addr is other guy
    sendp(Ether(dst=new_packet.mac_addr)/ARP(hwdst=new_packet.mac_addr, pdst=new_packet.dest_ip, psrc=new_packet.src_ip), "ethernet")




#Prevention:
#send junk packet, entrap them
#Getting a response when no request made
#use timestamps
#make as a daemon (fork child process and then exit parent)
#TODO: "ethernet" -> interface
