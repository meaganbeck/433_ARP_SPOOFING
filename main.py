#!/usr/bin/python3

import os
import re
import time
import socket
import subprocess


try:
	import netifaces
except ModuleNotFoundError:
	print("Make sure you are using Python 3.7+ and have installed the following dependencies:")
	print("netifaces (pip3 install netifaces)") 
	exit()

def main(): 
	# Scan for interface names 
	network_interfaces = netifaces.interfaces()

	for i in range(len(network_interfaces)): 
		interface_name = network_interfaces[i]
		if not (interface_name.startswith('lo')): # skip loopback interfaces
			addresses = netifaces.ifaddresses(interface_name)
			interface_IP = addresses[netifaces.AF_INET][0]['addr']
			interface_MAC = addresses[netifaces.AF_LINK][0]['addr']
			print("Interface: " + interface_name)
			print("MAC: " + interface_MAC)
			print("IP: " + interface_IP) 
			subprocess.Popen(["./packet_sniffer.py", interface_name, interface_IP, interface_MAC])
	return 0

if __name__ == "__main__":
	main()