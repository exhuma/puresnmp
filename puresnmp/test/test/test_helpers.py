'''
Tests for unit-test helpers
'''

from textwrap import dedent
from binascii import hexlify
import puresnmp.test as th
from io import StringIO


def test_readbytes_multiple():
    data = StringIO(dedent(
        '''\
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
