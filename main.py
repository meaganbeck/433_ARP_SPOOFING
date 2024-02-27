#!/usr/bin/python3

import os
import re
#import pyshark # "my dependencies aren't working for some reason" -H  
import time
import socket
import netifaces # pip3 install netifaces


def main(): 

	# TODO: Ensure user has correct dependencies installed
		# option 1: throw an error if they don't, have them install themselves with pip3
		# option 2: run some sort of script to install the dependencies for them 
		

	# unclear if socket module needed? 
	hostname = socket.gethostname()
	myIp = socket.gethostbyname(hostname)
	print("Host: " + hostname)


	# Scan for interface names 
	network_interfaces = netifaces.interfaces()
	for i in range(len(network_interfaces)): 
		interface_name = network_interfaces[i]
		addresses = netifaces.ifaddresses(interface_name)
		interface_MAC = addresses[netifaces.AF_LINK][0]['addr']
		interface_IP = addresses[netifaces.AF_INET][0]['addr']
		print("Interface: " + interface_name)
		print("MAC: " + interface_MAC)
		print("IP: " + interface_IP) 

		# TODO: 
		# Skip loopback interfaces 
		# pass the interface name, IP, MAC, and host name as arguments to read_packets.py 
		# use subprocess.Popen to create child processes (Popen is non-blocking, run is blocking)
		# probably fine for this parent process to terminate afterwards... 

	return 0

if __name__ == "__main__":
	main()