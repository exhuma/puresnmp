"""
Test the "external" interface.

The "external" interface is what the user sees. It should be pythonic and easy
to use.
"""


from collections import OrderedDict
from unittest.mock import patch
import unittest

from puresnmp import get, walk
from puresnmp.pdu import VarBind
from puresnmp.types import Gauge
from puresnmp.x690.types import ObjectIdentifier

from . import readbytes


class TestApi(unittest.TestCase):

    def test_get_call_args(self):
        """
        Test the call arguments of "get"
        """
        from puresnmp.x690.types import Integer, OctetString, Sequence, ObjectIdentifier
        from puresnmp.pdu import GetRequest
        from puresnmp.const import Version
        data = readbytes('get_sysdescr_01.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            GetRequest(0, ObjectIdentifier(1, 2, 3))
        )
        with patch('puresnmp.send') as mck, patch('puresnmp.get_request_id') as mck2:
            mck2.return_value = 0
            mck.return_value = data
            get('::1', 'public', '1.2.3')
            mck.assert_called_with('::1', 161, bytes(packet))

    def test_get_string(self):
        data = readbytes('get_sysdescr_01.hex')
        expected = (b'Linux d24cf7f36138 4.4.0-28-generic #47-Ubuntu SMP '
                    b'Fri Jun 24 10:09:13 UTC 2016 x86_64')
        with patch('puresnmp.send') as mck:
            mck.return_value = data
            result = get('::1', 'private', '1.2.3')
        self.assertEqual(result, expected)

    def test_get_oid(self):
        data = readbytes('get_sysoid_01.hex')
        expected = ('1.3.6.1.4.1.8072.3.2.10')
        with patch('puresnmp.send') as mck:
            mck.return_value = data
            result = get('::1', 'private', '1.2.3')
        self.assertEqual(result, expected)

    def test_walk(self):
        request_1 = readbytes('walk_request_1.hex')
        response_1 = readbytes('walk_response_1.hex')
        request_2 = readbytes('walk_request_2.hex')
        response_2 = readbytes('walk_response_2.hex')
        request_3 = readbytes('walk_request_3.hex')
        response_3 = readbytes('walk_response_3.hex')

        num_call = 0

        def mocked_responses(*args, **kwargs):
            nonlocal num_call
            num_call += 1
            if num_call == 1:
                return response_1
            elif num_call == 2:
                return response_2
            elif num_call == 3:
                return response_3
            else:
                raise AssertionError('Expected no more than 3 calls!')

        expected = [VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.5.1'),
            Gauge(10000000)
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.5.13'),
            Gauge(4294967295)
        )]

        with patch('puresnmp.send') as mck:
            mck.side_effect = mocked_responses
            result = list(walk('::1', 'public', '1.3.6.1.2.1.2.2.1.5'))
        self.assertEqual(result, expected)

    def test_multi_walk(self):
        self.skipTest('According to the spec a "walk" with multiple OIDs '
                      'should be possible')  # TODO

    def test_set(self):
        self.skipTest('TODO')
