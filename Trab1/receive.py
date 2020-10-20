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

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]

class intPai(Packet):
    name = "intPai"
    fields_desc = [ BitField("Quantidade_Filhos", 0, 32)]

class intFilho(Packet):
    name = "intFilho"
    fields_desc = [ BitField("ID_Switch", 0x0, 32),
                    BitField("Porta_Entrada", 0x0, 9),
                    BitField("Porta_Saida", 0x0, 9),
                    BitField("Timestamp", 0x0, 48), 
                    BitField("padding", 0x0, 6)]

bind_layers(IP, intPai, flags=1)

def handle_pkt(pkt):
    print pkt

    try:
        if (IP in pkt) and (pkt[IP].flags % 2 != 0):
            # First flag (reserved) is set to 1 i.e. there is a int header
            print('IP packet with odd IP flags value')
            hdrIntPai = pkt[intPai]
            if (hdrIntPai):
                print('INT pai header in packet')
                nChildren = pkt[intPai].Quantidade_Filhos
                print('INT with nChildren=' + Quantidade_Filhos)
            else:
                print('INT pai header NOT in packet')


            # a = pkt[IP].payload
            # print a
            # p = intPai(a)
            # i = p[intPai].Quantidade_Filhos #provavelmente errado
            # print "Numero de intFilhos: " + i
            # for i in range(i):
            #     print "ID:" + pkt[intFilho].ID_Switch + "\n Porta Entrada:" + pkt[intFilho].Porta_Entrada + "\n Porta Saida:" + pkt[intFilho].Porta_Saida + "\n Timestamp:" + pkt[intFilho].Timestamp #certamente errado
        else:
            if TCP in pkt and pkt[TCP].dport == 1234:
                print "got a TCP packet without INT"             
                pkt.show2()
            #    hexdump(pkt)
                sys.stdout.flush()
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
