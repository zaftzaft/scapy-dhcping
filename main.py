#!/usr/bin/env python3
import threading
import argparse
import time
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

parser = argparse.ArgumentParser()

parser.add_argument("-i", "--iface", required=False, help="interface", default=None)
parser.add_argument("-t", "--timeout", required=False, help="timeout", default=3)

args = parser.parse_args()

seq = 0
xid = random.randint(0, 0xFFFF)
exit_code = 1 # timeout

def callback(pkt):
    global seq
    global exit_code

    if DHCP in pkt:
        bootp = pkt[BOOTP]
        dhcp = pkt[DHCP]

        if bootp.xid != xid:
            return


        for opt in pkt[DHCP].options:
            if "message-type" in opt:
                mtype = opt[1]

        # DHCP Offer (discover response)
        if mtype == 2:
            print("{},{},{:.2f}".format(pkt[IP].src, bootp.yiaddr, time.time() - start))
            exit_code = 0
            seq += 1


def loop():
    sniff(prn=callback, stop_filter = lambda x: seq == 1, iface=args.iface, timeout=args.timeout)

sn = threading.Thread(target=loop, name="main")
sn.start()


start = time.time()
sendp(
    Ether(dst="ff:ff:ff:ff:ff:ff")/
    IP(src="0.0.0.0",dst="255.255.255.255")/
    UDP(sport=68,dport=67)/
    BOOTP(chaddr="0.0.0.0",xid=xid)/
    DHCP(options=[('message-type','discover'),('end')]),
    verbose=False, iface=args.iface
)


while True:
    if not sn.is_alive():
        sys.exit(exit_code)

    time.sleep(0.05)

