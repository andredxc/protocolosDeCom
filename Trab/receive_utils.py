from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from scapy.all import bind_layers
from int_headers import IntPai, IntFilho

c_nTCPHeaderLenBytes = 20
INFO_PROTOCOL = 145
ICMP_PROTOCOL = 1

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

    print('New packet --------------------------------')

    if (IP in pkt):
        print('IP header in packet')
        if (pkt[IP].flags == 4 or pkt[IP].flags == 5 or pkt[IP].flags == 6 or pkt[IP].flags == 7):
            print('Evil bit is set')
            fullPayload = bytes(pkt[IP].payload)
            # Parse IntPai header
            intPaiHdr = IntPai(fullPayload)
            print('Parsed IntPai header: %s' % str(intPaiHdr))
            
            # Parse IntFilho headers
            nStartIndex = intPaiHdr.nLengthBytes
            for i in range(0, intPaiHdr.nChildren):
                payload      = fullPayload[nStartIndex : nStartIndex + intPaiHdr.nChildLength]
                newIntFilho  = IntFilho(payload)
                nStartIndex += intPaiHdr.nChildLength
                print('Read IntFilho[%d] header: %s' % (i, str(newIntFilho)))

            # Read TCP payload
            nStartIndex = intPaiHdr.nLengthBytes + (intPaiHdr.nChildLength * intPaiHdr.nChildren) + c_nTCPHeaderLenBytes
            tcpPayload  = fullPayload[nStartIndex:]
            print('TCP payload received: %s' % tcpPayload)
        else:
            print('Evil bit is not set, flags=' + str(pkt[IP].flags))
            # Read TCP payload
            if(pkt[IP].proto == INFO_PROTOCOL):
                print('Info packet received!!')
                fullPayload = bytes(pkt[IP].payload)
                # Parse IntPai header
                intPaiHdr = IntPai(fullPayload)
                print('Parsed IntPai header: %s' % str(intPaiHdr))
                
                # Parse IntFilho headers
                nStartIndex = intPaiHdr.nLengthBytes
                for i in range(0, intPaiHdr.nChildren):
                    payload      = fullPayload[nStartIndex : nStartIndex + intPaiHdr.nChildLength]
                    newIntFilho  = IntFilho(payload)
                    nStartIndex += intPaiHdr.nChildLength
                    print('Read IntFilho[%d] header: %s' % (i, str(newIntFilho)))

                # Read TCP payload
                nStartIndex = intPaiHdr.nLengthBytes + (intPaiHdr.nChildLength * intPaiHdr.nChildren) + c_nTCPHeaderLenBytes
                tcpPayload  = fullPayload[nStartIndex:]
                print('TCP payload received: %s' % tcpPayload)
            else:
                if(TCP in pkt):
                    print('TCP payload: %s' % str(pkt[TCP].payload))
                else:
                    if(pkt[IP].proto == 1):
                        print('ICMP protocol')
                    else:
                        print('Unknown protocol.')
                #print("Protocol: %s" % str(pkt[IP].proto))
    else:
        print('Not an IP packet')