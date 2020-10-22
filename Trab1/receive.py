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

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

# class IntPai(Packet):
#     name = "IntPai"
#     fields_desc = [ BitField("Quantidade_Filhos", 0x0, 32)]

# bind_layers(IP, IntPai, flags=4)

# class IntFilho(Packet):
#     name = "IntFilho"
#     fields_desc = [ BitField("ID_Switch", 0x0, 32),
#                     BitField("Porta_Entrada", 0x0, 9),
#                     BitField("Porta_Saida", 0x0, 9),
#                     BitField("Timestamp", 0x0, 48), 
#                     BitField("padding", 0x0, 6)]

def hexToInt(strBytes, length=len(strBytes)):
    """
    Converts length amount of bits from strHex to int
    """
    strHex = strBytes.encode('hex')
    strBin = ''
    for strVal in range(min(len(strHex), length)):
        strBin += "{0:0b}".format(int(strVal, 16))

    return int(strBin, 2)

def handle_pkt(pkt):

    try:
        if (IP in pkt):
            print('IP header in packet')
            if (pkt[IP].flags == 4):
                print('Evil bit is set')
                initPayload = bytes(pkt[IP].payload)

                # "{0:08b}".format(int(strHex, 16))
                # codecs.encode(strHex, 'hex')

                nChildSize  = int(codecs.encode(initPayload[0:4], 'hex'), 16)
                nChildren   = int(codecs.encode(initPayload[4:8], 'hex'), 16)
                print('nChildren=%d; nChildSize=%d' % (nChildren, nChildSize))

                nIndex = 8
                for i in range(0, nChildren):
                    payload    = initPayload[nIndex:nIndex + nChildSize]
                    nSwitchID  = int(codecs.encode(payload[0:4], 'hex'), 16)
                    nTimestamp = int(codecs.encode(payload[6:12], 'hex'), 16)
                    # nInPort    = int(codecs.encode(payload[4:5], 'hex'), 16)
                    # nOutPort   = int(codecs.encode(payload[5:6], 'hex'), 16)
                    nInPort    = hexToInt(payload[4:6], 9)
                    nOutPort   = hexToInt(payload[4:6], 9)
                    nOutPort   = 0
                    nIndex    += nChildSize
                    print('Read header=%d; SwitchID=%d; InPort=%d; OutPort=%d; Timestamp=%d' %
                        (i, nSwitchID, nInPort, nOutPort, nTimestamp))
            else:
                print('Evil bit is not set, flags=' + pkt[IP].flags)
        else:
            print('NOT an IP packet')

            """
            strHex = load.encode('hex')
            "{0:08b}".format(int(strHex, 16))
            codecs.encode(strHex, 'hex')

            """

    except Exception as inst:
        print('Caught exception in handle_pkt, printing packet')
        pkt.show2()
        raise inst

def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print ("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
