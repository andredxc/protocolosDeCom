"""
23/10/2020
Andre Dexheimer Carneiro (00243653) e Rubens Ideron (????????)
"""

from utils import hexToInt

class IntPai:
    """
    Represents an IntPai header
    bit<32> Child length;
    bit<32> Number of children;
    """
    def __init__(self, payload=None):
        if (payload is not None): 
            self.fromPayload(payload)
        else:
            self.nChildLength  = 0
            self.nChildren     = 0
        
        self.nLengthBytes  = 8

    def __repr__(self):
        return '<IntPai> ChildLength=%d; Children=%d; HeaderLength=%d' % (self.nChildLength, self.nChildren, self.nLengthBytes)

    def fromPayload(self, payload):
        """
        Parses header from hex payload, starting at index 0
        """
        self.nChildLength = int(payload[0:4].encode('hex'), 16)
        self.nChildren    = int(payload[4:8].encode('hex'), 16)

class IntFilho:
    """
    Represents an IntFilho header
    bit<32> Switch ID;
    bit<48> Timestamp;
    bit<9>  In port;
    bit<9>  Out port;
    bit<6>  padding;
    """
    def __init__(self, payload=None):
        if (payload is not None):
            self.fromPayload(payload)
        else:
            self.nSwitchID  = 0
            self.nTimestamp = 0
            self.nInPort    = 0
            self.nOutPort   = 0
        
        self.nLengthBytes = 13

    def __repr__(self):
        return '<IntFilho> SwitchID=%d; Timestamp=%d; InPort=%d; OutPort=%d; HeaderLength=%d' % (self.nSwitchID, self.nTimestamp, self.nInPort, self.nOutPort, self.nLengthBytes)

    def fromPayload(self, payload):
        """
        Parses header from hex payload, starting at index 0
        """
        self.nSwitchID  = hexToInt(payload[0:4])
        self.nTimestamp = hexToInt(payload[4:10])
        self.nInPort    = hexToInt(payload[10:13], paddingLeft=0, length=9)
        self.nOutPort   = hexToInt(payload[10:13], paddingLeft=9, length=9)     