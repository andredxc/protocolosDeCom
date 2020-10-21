#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from scapy.all import bind_layers
import pickle

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IntPai(Packet):
    name = "IntPai"
    fields_desc = [ BitField("Quantidade_Filhos", 0x0, 32)]

bind_layers(IP, IntPai, flags=4)

class IntFilho(Packet):
    name = "IntFilho"
    fields_desc = [ BitField("ID_Switch", 0x0, 32),
                    BitField("Porta_Entrada", 0x0, 9),
                    BitField("Porta_Saida", 0x0, 9),
                    BitField("Timestamp", 0x0, 48), 
                    BitField("padding", 0x0, 6)]

def handle_pkt(pkt):
    print pkt

    try:
        if (IP in pkt):
            print('IP header in packet')
            if (pkt[IP].flags == 4):
                print('Evil bit is set')
                hdrIntPai = pkt[IntPai]
                if (hdrIntPai):
                    print('INT header in  packet')
                    nChildren = pkt[intPai].Quantidade_Filhos
                    print('nChildren=' + Quantidade_Filhos)
                else:
                    print('No INT header in packet')
            else:
                print('Evil bit is not set, flags=' + pkt[IP].flags)
        else:
            print('NOT an IP packet')

    except Exception as inst:
        print('Caught exception in handle_pkt, printing packet')
        pkt.show2()
        raise inst

def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
