#!/usr/bin/python3

import os
import re
import time
import socket

def outgoing_ARP_hash(hashtable, packet):
    """Store outgoing packet into the hash table"""
    hashtable[packet.ip_addr] = packet 

def remove_ARP_hash(hashtable, packet):
    """Remove packet from hash table upon response or timeout"""
    del hashtable[packet.ip_addr]

def check_hash(hashtable, packet):
    """Check if there is a packet from a specific IP address in hash"""
    if packet.ip_addr in hashtable.keys():
	    return True
    else:
        return False

def purge_hash(hashtable):
    current_time = time.time()
    for key in hashtable.keys():
        if (current_time - hashtable[key].timestamp) > 2:
            del hash_table[key]

