#!/usr/bin/python3

import time
from sys import argv
from arp_cache import * 
from outgoing_hash import *

try: 
    import pyshark 
    from scapy.all import *
except ModuleNotFoundError: 
    print("Make sure you are using Python 3.7+ and have installed the following dependencies:")
    print("pyshark (pip3 install pyshark)")
    print("scapy (pip3 install scapy)")
    print("tshark (sudo apt install tshark)")
    exit()
    
def create_arp_reply(new_packet):
    # This line is giving me some warnings. I don't know why. 
    sendp(Ether(dst=new_packet.mac_addr)/ARP(hwdst=new_packet.mac_addr, pdst=new_packet.dest_ip, psrc=new_packet.src_ip), my_name)


# argv contains: Interface name, interface ip, interface mac (in that order).
# argv[0] is just the path to this script. Ignore it. 
my_name = argv[1]
my_IP = argv[2]
my_MAC = argv[3]

class Packet:
    mac_addr = 0
    src_ip = 0
    dest_ip = 0
    opcode = 0
    expiry = 0
    complete = False

if os.geteuid() != 0:
    print("Error: Script requires root privileges.")
    exit()

arp_cache = {}
request_queue = {}


try:
    capture = pyshark.LiveCapture(interface=my_name, bpf_filter='arp')

    # sniff for packets continuously
    for packet in capture.sniff_continuously():
        # print("Sniffing...")

        #store packet data
        arp_layer = packet['ARP']
        packet_info = Packet()
        packet_info.opcode = int(arp_layer.opcode, 16)
        packet_info.mac_addr = packet.eth._all_fields.values()
        packet_info.src_ip = packet.ip.src
        packet_info.dest_ip = packet.ip.dst
        
        if packet_info.src_ip == my_IP: #outgoing
            #add to request queue
            print(f"Outgoing request to address {packet_info.dest_ip}")
            packet_info.expiry = time.time() + 2
            enqueue(request_queue, packet)
            purge_queue(request_queue)

        elif packet_info.dest_ip == my_IP: #incoming

            if packet_info.opcode == 1: # request 
                pass 
                # print(f"Incoming request from address {packet_info.src_ip}")
                # check the arp cache. if a mapping exists whose entry does not match the one in the request, the person who sent it is spoofing
                    # purge related entries from the arp cache 
                    # do not respond 
                # otherwise 
                    # construct new packet with my information 
                    # input into create_arp_reply

            elif packet_info.opcode == 2: # reply
                pass 
                # print(f"Incoming reply from address {packet_info.src_ip}") 
                # TODO: rewrite
                # check request queue 
                # if a corresponding request is present but already complete: 
                    # purge related entries from the arp cache
                    # purge the request from the request queue 
                    # send a new arp request to the relevant ip
                # if a corresponding request is present but incomplete, and not expired: 
                    # reply to it normally 
                    # mark the request as complete
                # otherwise do nothing 
                pass 
            
except KeyboardInterrupt:
    print("")
    print("Exiting...")
    exit() 


                
