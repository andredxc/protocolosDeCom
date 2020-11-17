import sys
import struct
import os
import codecs
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr

from receive_utils import get_if, handle_pkt

def main():
    global iface
    if len(sys.argv) >= 2:
        iface = sys.argv[1]
    else:
        ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
        iface = ifaces[0]
    print ("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
