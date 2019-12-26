from os.path import dirname

HERE = dirname(__file__)

from puresnmp.pdu import PDU
from puresnmp.test import readbytes_multiple
from puresnmp.x690.types import pop_tlv

for row in readbytes_multiple("authpriv.hex", HERE):
    print(row)
    pdu, _ = pop_tlv(row)
    print(pdu.pretty())
