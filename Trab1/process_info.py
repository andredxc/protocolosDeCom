#23/10/2020
#Andre Dexheimer Carneiro (00243653) e Rubens Ideron (00243658)
#Must run on h1 (10.0.1.1)

#!/usr/bin/env python
import sys
import struct
import os
import codecs

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from scapy.all import bind_layers
from int_headers import IntPai, IntFilho

c_nTCPHeaderLenBytes = 20

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def handle_pkt(pkt):

    if (IP in pkt):
        print('\nIP header in packet')
        if(pkt[IP].proto == 145):
            print("Info received.")
            fullPayload = bytes(pkt[IP].payload)
            # Parse IntPai header
            intPaiHdr = IntPai(fullPayload)
            print('Parsed IntPai header: %s' % str(intPaiHdr))

            print('load: ' + str(pkt[Raw].load))
            
            # Parse IntFilho headers
            nStartIndex = intPaiHdr.nLengthBytes
            for i in range(0, intPaiHdr.nChildren):
                payload      = fullPayload[nStartIndex : nStartIndex + intPaiHdr.nChildLength]
                newIntFilho  = IntFilho(payload)
                nStartIndex += intPaiHdr.nChildLength
                print('Read IntFilho[%d] header: %s' % (i, str(newIntFilho)))
        else:
            print("Not an INFO packet.")
    else:
        print('Not an IP packet')

def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print ("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
