"""
23/10/2020
Andre Dexheimer Carneiro (00243653) e Rubens Ideron (????????)
"""

def hexToInt(strBytes, paddingLeft=0, length=-1):
    """
    Converts custom length hex to int
    """

    # Parse byte string to a bit string
    strHex = strBytes.encode('hex')
    strBin = ''
    # print('hexToInt: strHex=%s' % strHex)
    for strChar in strHex:
        strBin += "{0:04b}".format(int(strChar, 16))
        # print('hexToInt: strBin=%s, strChar=%s' % (strBin, strChar))

    # Extract value based on paddingLeft and length from bit string
    if (length < 0):
        length = len(strBin)

    # print('hexToInt: Before substring, strBin=%s' % strBin)
    strBin = strBin[paddingLeft:min(paddingLeft+length, len(strBin))]
    # print('hexToInt: After substring, strBin=%s' % strBin)

    # print('hexToInt: final strBin=%s' % strBin)
    return int(strBin, 2)   