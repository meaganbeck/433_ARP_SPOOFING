#!/usr/bin/python3

import time
from sys import argv
from arp_cache import * 
from manage_requests import *

try: 
    import pyshark 
    from scapy.all import *
except ModuleNotFoundError: 
    print("Make sure you are using Python 3.7+ and have installed the following dependencies:")
    print("pyshark (pip3 install pyshark)")
    print("scapy (pip3 install scapy)")
    print("tshark (sudo apt install tshark)")
    exit()


# argv contains: Interface name, interface ip, interface mac (in that order).
# argv[0] is just the path to this script. Ignore it. 
my_name = argv[1]
my_IP = argv[2]
my_MAC = argv[3]

class Packet_Info:
    def __init__(self, mac_src, mac_dest, src, dest, opcode):
        self.src_mac = mac_src
        self.dest_mac = mac_dest 
        self.src_ip = src
        self.dest_ip = dest
        self.opcode = 0
        self.expiry = 0
        self.complete = False
    def __str__(self):
        return f"== PACKET == \n Source MAC: {self.src_mac} \n Destination MAC: {self.dest_mac} \n Source IP: {self.src_ip} \n Destination IP: {self.dest_ip} \n Opcode: {self.opcode}"
    

if os.geteuid() != 0:
    print("Error: Script requires root privileges.")
    exit()

arp_cache = {} # keyed by source ip 
request_queue = {} # keyed by destination ip 
alarm = 0

# TODO: REWRITE ARP_CACHE.PY FUNCTIONS AND ADD CALLS TO THEM

try:
    print(f"Beginning live capture on interface {my_name}...")
    capture = pyshark.LiveCapture(interface=my_name, bpf_filter='arp')

    # sniff for packets continuously
    for packet in capture.sniff_continuously():
       # print("Sniffing...") 

        # Every few seconds, purge the request queue of expired requests 
        if (time.time() - alarm >= 4):
            purge_queue(request_queue)
            alarm = time.time()

        #store packet data
        arp_layer = packet['ARP']
        packet_deets = Packet_Info(arp_layer.src_hw_mac, arp_layer.dst_hw_mac, arp_layer.src_proto_ipv4, arp_layer.dst_proto_ipv4, int(arp_layer.opcode, 16))
        
        if (packet_deets.src_ip == my_IP and packet_deets.opcode == 1): #outgoing request
            print(f"Outgoing request to address {packet_deets.dest_ip}")
            # add to request queue
            packet_deets.expiry = time.time() + 2
            enqueue(request_queue, packet)

        elif packet_deets.dest_ip == my_IP: #incoming

            if packet_deets.opcode == 1: # request 
                print(f"Incoming request from address {packet_deets.src_ip}")
                # check the arp cache. if a mapping exists whose entry does not match the one in the request, the person who sent it is spoofing
                if (packet_deets.src_ip in arp_cache):
                    if (arp_cache[packet_deets.src_ip].src_mac != packet_deets.src_mac):
                        print("Spoofed request detected. Purging...")
                        del arp_cache[packet_deets.src_ip] # purge the entry from the arp cache 
                        subprocess.run(["arp", "-d", f"{packet_deets.src_ip}"])

            elif packet_deets.opcode == 2: # reply
                print(f"Incoming reply from address {packet_deets.src_ip}") 
                # Check request queue. if a corresponding request is present (reply was solicited):
                if (packet_deets.src_ip in arp_cache):
                    # if the request is marked complete (i.e. we received two replies to it): 
                    if arp_cache[packet_deets.src_ip].complete: 
                        print("Spoofed reply detected. Purging...")
                        del arp_cache[packet_deets.src_ip] # purge the entry from the arp cache
                        subprocess.run(["arp", "-d", f"{packet_deets.src_ip}"]) # purge the request from the request queue 
                        # optional: generate a new arp request and send it to the ip in question
                # if it is incomplete AND not expired: generate a reply as normal 
                    # the arp module will do this as normal and we don't need to do anything 
                else: # otherwise it's unsolicited and we don't want it in the arp cache 
                    print("Unsolicited reply detected. Purging...")
                    subprocess.run(["arp", "-d", f"{packet_deets.src_ip}"]) 
                 
except KeyboardInterrupt:
    print("")
    print("Exiting...")
    exit() 


                
