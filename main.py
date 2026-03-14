#!/usr/bin/python3

import os
import re
import time
import socket

try:
    import netifaces
    import subprocess
except ModuleNotFoundError:
    print("Please ensure that you have installed the netifaces module for python (pip3 install netifaces).") # except net-tools is deprecated 
    exit()

def main(): 
	# Scan for interface names 
    network_interfaces = netifaces.interfaces()

    for i in range(len(network_interfaces)): 
        interface_name = network_interfaces[i]
        if not (interface_name.startswith('lo')): pass # skip loopback interfaces
        addresses = netifaces.ifaddresses(interface_name) # store the addresses associated with the interface
        interface_IP = addresses[netifaces.AF_INET][0]['addr'] 
        interface_MAC = addresses[netifaces.AF_LINK][0]['addr'] # and the corr address associated at link layer 
        print("Interface: " + interface_name)
        print("MAC: " + interface_MAC)
        print("IP: " + interface_IP) 
        subprocess.Popen(["./packet_sniffer.py", interface_name, interface_IP, interface_MAC]) # and now invoke packet_sniffer using the stored arguments
    return 0

if __name__ == "__main__":
    main()
