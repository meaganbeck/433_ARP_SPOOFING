#!/usr/bin/python3
import time

def cache_request(request_cache, packet):
    """Store outgoing packet into the hash table"""
    request_cache[packet.dest_ip] = packet 

def purge_requests(request_cache):
    """Remove expired requests from the cache."""
    current_time = time.time()
    for ip in request_cache:
        if current_time > request_cache[ip].expiry:
            del request_cache[ip]

