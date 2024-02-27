import subprocess

def block_arp_cache():

#dir == stop arp cache
#TODO: "ethernet" fix
    #block from responding to ANY arp request
    result = subprocess.run(["sysctl", f"net.ipv4.conf.ethernet.arp_ignore=8"], shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print("success")
    else:
        print(result.stdout)

def block_gratuitous():
    #drop gratuitous arp requests
    result = subprocess.run(["sysctl",f"net.ipv4.conf.ethernet.arp_accept=0"], shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("success")
        else:
            print(result.stdout)

def notify_user():

#proxy_arp?

