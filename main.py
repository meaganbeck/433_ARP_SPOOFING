#!/usr/bin/python3

import os
import re
import pyshark
import time
import socket
import arp_cache
import read_packets


def main(): 
	#TODO: 
	#Block OS from doing things with packets/updating ARP caches autonomously (we want to control that)
	#Fork child process 
	#Terminate parent 
	#Open the correct socket 
	#Read packets using read_packets.py
	return 0

if __name__ == "__main__":
	main()