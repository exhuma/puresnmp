'''
Tests for unit-test helpers
'''

from textwrap import dedent
from binascii import hexlify
import puresnmp.test as th
from io import StringIO


def test_readbytes_multiple():
    data = StringIO(dedent(
        u'''\
        #
        # This is a comment
        #

        30 2d 02 01 01 04 07 70  72 69 76 61 74 65 a2 1f   0-.....private..

        ----

        30 2d 02 01 01 04 07 70  72 69 76 61 74 65 a2 1f   0-.....private..

        ----

        30 2e 02 01 01 04 07 70  72 69 76 61 74 65 a2 20   0......private.
        '''
    ))
    expected = [
        b'\x30\x2d\x02\x01\x01\x04\x07\x70\x72\x69\x76\x61\x74\x65\xa2\x1f',
        b'\x30\x2d\x02\x01\x01\x04\x07\x70\x72\x69\x76\x61\x74\x65\xa2\x1f',
        b'\x30\x2e\x02\x01\x01\x04\x07\x70\x72\x69\x76\x61\x74\x65\xa2\x20',
    ]

    result = list(th.readbytes_multiple(data))

    assert result == expected


def test_readbytes_multiple_byte_positions():
    '''
    If ASCII columns are defined, we should still properly split the packets
    '''
    data = StringIO(dedent(
        u'''\
        # -*- ascii-cols: 6-56 -*-
        # Sequence of responses for an SNMP Walk operation which eventually falls into
        # a special "endOfMibView" marker (a varbind with binary *value* 0x82 0x00).

        0000: 30 37 02 01  01 04 07 70  72 69 76 61  74 65 A2 29    07.....private.)

        ----

        0000: 31 37 02 01  01 04 07 70  72 69 76 61  74 65 A2 29    07.....private.)
        '''
    ))

    expected = [
        b'\x30\x37\x02\x01\x01\x04\x07\x70\x72\x69\x76\x61\x74\x65\xA2\x29',
        b'\x31\x37\x02\x01\x01\x04\x07\x70\x72\x69\x76\x61\x74\x65\xA2\x29',
    ]

    result = list(th.readbytes_multiple(data))

    assert result == expected


def test_readbytes():
    data = StringIO(dedent(
        u'''\
        0000: 30 29 02 01  01 04 07 70  72 69 76 61  74 65 A5 1B    0).....private..
        '''
    ))

    expected = b'\x30\x29\x02\x01\x01\x04\x07\x70\x72\x69\x76\x61\x74\x65\xA5\x1B'
    result = th.readbytes(data)
    assert result == expected


def test_chunker():
    data = [1, 2, -1, 3, 4]
    expected = [[1, 2], [3, 4]]
    result = list(th.chunker(data, is_boundary=lambda x: x == -1))
    assert result == expected

    data = [-1, 1, 2, -1, 3, 4]
    expected = [[1, 2], [3, 4]]
    result = list(th.chunker(data, is_boundary=lambda x: x == -1))
    assert result == expected

    data = [1, 2, -1, 3, 4, -1]
    expected = [[1, 2], [3, 4]]
    result = list(th.chunker(data, is_boundary=lambda x: x == -1))
    assert result == expected

    data = [-1]
    expected = []
    result = list(th.chunker(data, is_boundary=lambda x: x == -1))
    assert result == expected

    data = []
    expected = []
    result = list(th.chunker(data, is_boundary=lambda x: x == -1))
    assert result == expected
