#!/usr/bin/python3

import os
import re
import time
import socket

def enqueue(request_queue, packet):
    """Store outgoing packet into the hash table"""
    request_queue[packet.ip_addr] = packet 

def dequeue(request_queue, packet):
    """Remove packet from hash table upon response or timeout"""
    del request_queue[packet.ip_addr]

def check_request(request_queue, packet):
    """Check if there is a packet from a specific IP address in hash"""
    if packet.ip_addr in request_queue.keys():
        return True
    else:
        return False

def purge_queue(request_queue):
    pass 

