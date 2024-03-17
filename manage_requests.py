#!/usr/bin/python3
import time

def enqueue(hash_table, packet):
    """Store outgoing packet into the hash table"""
    hash_table[packet.ip_addr] = packet 

def dequeue(hash_table, packet):
    """Remove packet from hash table upon response or timeout"""
    del hash_table[packet.ip_addr]

def purge_queue(hash_table):
    current_time = time.time()
    for key in hash_table.keys():
        if (current_time - hash_table[key].timestamp) > 2:
            del hash_table[key]

