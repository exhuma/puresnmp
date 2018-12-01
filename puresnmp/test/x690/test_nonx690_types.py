'''
SNMP logic should not leak *down* into the x690 layer. The other way around is
correct
'''

from puresnmp.test import readbytes, readbytes_multiple
from puresnmp.x690.types import pop_tlv, Integer
import pytest



def test_bulk_get():
    data = readbytes('x690/bulk_get_eom_response.hex')
    result, _ = pop_tlv(data)
    _, _, response_object = result

    root = '1.3.6.1.6.3.16.1.5.2.1.6.6.95.110.111.110.101.95.1.'
    expected = [
        (root+'0', Integer(1)),
        (root+'1', Integer(1)),
        (root+'2', Integer(1)),
    ]

    simplified_result = [
        (str(oid), value) for oid, value in response_object.varbinds
    ]

    assert simplified_result == expected
