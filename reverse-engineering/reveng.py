# pylint: skip-file
import sys
from os.path import dirname

from hexlib import readbytes_multiple
from x690.types import pop_tlv

from puresnmp.pdu import PDU

HERE = dirname(__file__)


for row in readbytes_multiple(sys.argv[1], HERE):
    data, _ = pop_tlv(row)
    print(data.pretty())
