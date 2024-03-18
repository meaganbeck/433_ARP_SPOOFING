# ArpEyeMini
**#Overview:**\
This software is intended to detect and mitigate ARP spoofing attacks on a local network. ARP spoofing is a common attack over a network in which the attacker sends ARP messages to the user, claiming to possess an IP address that is not their own. This leads to traffic being redirected to the attacker's machine.

**#Features:**\
Continuous capture of ARP packets on the user’s network interface.
Detection of both incoming and outgoing ARP requests and replies.
Detection of ARP spoofing attempts by comparing ARP cache entries with incoming ARP packets.
Removal of suspicious ARP cache entries and dropping of associated packets. 

**#Requirements:**\
Python 3.7 or newer
A Linux machine, running Ubuntu or Kali Linux

**#Dependencies:**\
PyShark - install via pip3 install pyshark
Scapy - install via pip3 install scapy
Netifaces - install via pip3 install netifaces
Tshark - install via sudo apt install tshark

**#Usage:**\
ArpEyeMini is a terminal-based program. The subprocesses for each interface will run until killed; the main "watchdog" program performs cleanup and resets kernel parameters to their default settings. 

To run ArpEyeMini, navigate inside the program folder, open a terminal, and run the following command: 
  sudo -E python3 main.py

The program will begin capturing ARP packets on the local network interface.
If suspicious activity is detected, the script will take actions to mitigate the threat, removing ARP cache entries and dropping suspicious packets. 

**#Credits:**\
Wireshark - This software relies on Wireshark, a network protocol analyzer.
  https://www.wireshark.org/
Scapy - This software relies on Scapy, a powerful interactive packet manipulation library. 
  https://scapy.net/

