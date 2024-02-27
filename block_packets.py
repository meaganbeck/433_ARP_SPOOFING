import subprocess
import os
import time
import socket
from scapy.all import * #dunno if using yet
#TODO: "ethernet" fix

def block_arp_cache(interface):
    #block from responding to ANY arp request
    result = subprocess.run(["sysctl", f"net.ipv4.conf.{interface}.arp_ignore=8"], shell=True, capture_output=True, text=True)
    #check success

    if result.returncode == 0:
        print("success in blocking response")
    else:
        print(result.stdout)

def block_gratuitous():
    #drop gratuitous arp requests
    result = subprocess.run(["sysctl",f"net.ipv4.conf.{interface}.arp_accept=0"], shell=True, capture_output=True, text=True)
        
        #check success
        if result.returncode == 0:
            print("success in dropping gratuitous packet")
        else:
            print(result.stdout)

