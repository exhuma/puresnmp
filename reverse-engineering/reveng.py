from puresnmp.test import readbytes_multiple
from puresnmp.pdu import PDU
from puresnmp.x690.types import pop_tlv

for row in readbytes_multiple('docker/authnopriv.hex'):
    print(row)
    pdu, _ = pop_tlv(row)
    print(pdu.pretty())
