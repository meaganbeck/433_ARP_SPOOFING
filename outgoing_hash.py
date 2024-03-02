#!/usr/bin/python3

import os
import re
import pyshark
import time
import socket

def outgoing_ARP_hash(hashtable, packet):
    """Store outgoing packet into the hash table"""
    hashtable[packet.ip_addr] = packet 

def remove_ARP_hash(hashtable, packet):
    """Remove packet from hash tale upon response or timeout"""
    del hashtable[packet.ip_addr]

def check_hash(hashtable, packet):
    """Check if there is a packet from a specific IP address in hash"""
    if packet.ip_addr in hashtable.keys():
	    return True
    else
        return False

