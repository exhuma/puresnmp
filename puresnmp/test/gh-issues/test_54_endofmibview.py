from puresnmp.test import readbytes
from unittest.mock import patch
from puresnmp.pdu import PDU
from puresnmp.x690.types import OctetString, Integer

from puresnmp.api.raw import bulkget
import pytest


def test_54_endofmibview():
    data = readbytes('gh-issues/54-endofmibview.hex')
    with patch('puresnmp.api.raw.send') as ptch:
        ptch.return_value = data
        result = bulkget('192.0.2.1', 'private', [], ['1.2.3'],
                 max_list_size=10)
    assert result.scalars == {}

    expected_lists = {
        '1.3.6.1.4.1.12325.1.303.1.9.1.3.1.0': OctetString(b'\x00'*404),
        '1.3.6.1.4.1.12325.1.303.1.9.1.3.2.0': OctetString(b'\x00'*404),
        '1.3.6.1.6.3.1.1.6.1.0': Integer(1103779487),
        '1.3.6.1.6.3.10.2.1.1.0': OctetString(b'\x80\x00\x08\xbe\x803740773355'),
        '1.3.6.1.6.3.10.2.1.2.0': Integer(1),
        '1.3.6.1.6.3.10.2.1.3.0': Integer(632),
        '1.3.6.1.6.3.10.2.1.4.0': Integer(1500),
    }
    assert result.listing == expected_lists
