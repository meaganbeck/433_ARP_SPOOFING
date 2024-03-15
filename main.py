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

if os.geteuid() != 0:
	print("Error: Script requires root privileges.")
	print("Try running this script with 'sudo -E'.")
	exit()

try:
	subprocess.run(["arp"])
except: 
	print("This program requires the arp utility (sudo apt install net-tools).")
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
			# Disable acceptance of gratuitious arp requests in the kernel
			print(f"Interface name: {interface_name}")
			print("Modifying kernel parameters...") 
			subprocess.run(["sysctl",f"net.ipv4.conf.{interface_name}.arp_accept=0"])
			sniffer = subprocess.Popen(['sudo', '-E', cur_dir + '/packet_sniffer.py', interface_name, interface_IP, interface_MAC])
			# ^^ This is probably not secure and you should never do this 
			sniffers.append(sniffer) 
	
	# Wait for children to terminate 
	for sniffer in sniffers: 
		sniffer.wait()

	# Reset kernel parameters to default 
	for i in range(len(network_interfaces)):
		interface_name = network_interfaces[i]
		if not (interface_name.startswith('lo')): 
			subprocess.run(["sysctl",f"net.ipv4.conf.{interface_name}.arp_accept=1"])

	return 
if __name__ == "__main__":
	main()