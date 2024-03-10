#!/usr/bin/python3

import os
import sys
import re
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
	cur_dir = os.getcwd()
	sniffers = []

	for i in range(len(network_interfaces)): 
		interface_name = network_interfaces[i]
		if not (interface_name.startswith('lo')): # Skip loopback interfaces 
			addresses = netifaces.ifaddresses(interface_name)
			interface_IP = addresses[netifaces.AF_INET][0]['addr']
			interface_MAC = addresses[netifaces.AF_LINK][0]['addr']
			sniffer = subprocess.Popen(['sudo', '-E', cur_dir + '/packet_sniffer.py', interface_name, interface_IP, interface_MAC])
			sniffers.append(sniffer) 
	
	# Wait for children to terminate 
	for sniffer in sniffers: 
		sniffer.wait()

	return 0

if __name__ == "__main__":
	main()