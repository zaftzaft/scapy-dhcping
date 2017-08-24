import threading
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


seq = 0
xid = random.randint(0, 0xFFFF)

def callback(pkt):
    global seq

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
            print("{},{}".format(pkt[IP].src, bootp.yiaddr))
            seq += 1


def loop():
    sniff(prn=callback, stop_filter = lambda x: seq == 1)

sn = threading.Thread(target=loop, name="main")
sn.start()


sendp(
    Ether(dst="ff:ff:ff:ff:ff:ff")/
    IP(src="0.0.0.0",dst="255.255.255.255")/
    UDP(sport=68,dport=67)/
    BOOTP(chaddr="0.0.0.0",xid=xid)/
    DHCP(options=[('message-type','discover'),('end')])
    ,verbose=False
)


