#!/usr/bin/python3

import os
import re
import time
import socket

def enqueue(hash_table, packet):
    """Store outgoing packet into the hash table"""
    hash_table[packet.ip_addr] = packet 

def dequeue(hash_table, packet):
    """Remove packet from hash table upon response or timeout"""
    del hash_table[packet.ip_addr]

def check_request(hash_table, packet):
    """Check if there is a packet from a specific IP address in hash"""
    # TODO: Modify 
    # return something different for if a request does not exist at all 
    # versus if a request exists but is marked 'complete'
    return (packet.ip_addr in hash_table.keys())

def purge_queue(hash_table):
    current_time = time.time()
    for key in hash_table.keys():
        if (current_time - hash_table[key].timestamp) > 2:
            del hash_table[key]

