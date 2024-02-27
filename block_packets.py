import subprocess
import os
import time
import socket
import scapy.all import * #dunno if using yet
import netifaces

#TODO: "ethernet" fix

logical_interface = netifaces.interfaces()

def block_arp_cache():
    #block from responding to ANY arp request
    result = subprocess.run(['sysctl', f'net.ipv4.conf.{logical_interface}.arp_ignore=8'], shell=True, capture_output=True, text=True)
    #check success

    if result.returncode == 0:
        print("success in blocking response")
    else:
        print(result.stdout)

def block_gratuitous():
    #drop gratuitous arp requests
    result = subprocess.run(["sysctl",f"net.ipv4.conf.{logical_interface}.arp_accept=0"], shell=True, capture_output=True, text=True)
        
        #check success
        if result.returncode == 0:
            print("success in dropping gratuitous packet")
        else:
            print(result.stdout)

