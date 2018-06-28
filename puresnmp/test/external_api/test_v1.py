# pylint: disable=missing-docstring
"""
Test the "external" interface in version 1.0.

This file should remain in the repository as long as we're still backwrds
compatible with 1.0.
"""


import datetime
import sys
from collections import OrderedDict
from typing import TYPE_CHECKING

import puresnmp as snmp
from puresnmp.const import Version
from puresnmp.pdu import GetResponse, VarBind
from puresnmp.x690.types import (Integer, ObjectIdentifier, OctetString,
                                 Sequence)

from .. import ByteTester, readbytes, readbytes_multiple

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from typing import Type


if sys.version_info >= (3, 0):
    from unittest.mock import patch
else:
    from mock import patch

OID = ObjectIdentifier.from_string
TESTS_SHOULD_RUN = snmp.__version__.startswith('1')


class TestGet(ByteTester):

    def setUp(self):
        patcher = patch('puresnmp.send')
        self._send = patcher.start()
        self.addCleanup(lambda: patcher.stop())  #pylint: disable=unnecessary-lambda

    def _create_response_pdu(self, response):
        # type: (Type) -> None
        '''
        Primes the network transport mock to return a valid SNMP response.
        '''
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            response
        )
        response_bytes = bytes(packet)
        return response_bytes

    def test_get(self):
        self._send.return_value = self._create_response_pdu(GetResponse(request_id=1, varbinds=[
            VarBind(ObjectIdentifier(1, 2, 3, 4), Integer(10)),
        ]))
        result = snmp.get('192.168.1.1', 'private', '1.3.6.1.2.1.1.2.0')
        self.assertEqual(result, 10)
        self._send.assert_called()

    def test_multiget(self):
        self._send.return_value = self._create_response_pdu(GetResponse(request_id=1, varbinds=[
            VarBind(ObjectIdentifier(1, 2, 3), Integer(10)),
            VarBind(ObjectIdentifier(2, 3, 4), Integer(20)),
        ]))
        result = snmp.multiget('192.168.1.1', 'private', ['1.2.3', '2.3.4'],
                               port=161, timeout=1)
        self.assertEqual(result, [10, 20])
        self._send.assert_called()

    def test_getnext(self):
        self._send.return_value = self._create_response_pdu(GetResponse(request_id=1, varbinds=[
            VarBind(ObjectIdentifier(1, 2, 4), Integer(10)),
        ]))
        result = snmp.getnext('192.168.1.1', 'private', '1.2.3',
                              port=161, timeout=1)
        expected = VarBind(ObjectIdentifier(1, 2, 4), 10)
        self.assertEqual(result, expected)
        self._send.assert_called()

    def test_bulkget(self):
        self._send.return_value = self._create_response_pdu(GetResponse(request_id=1, varbinds=[
            VarBind(OID('1.3.6.1.2.1.1.1.0'), OctetString(b'Some Text')),
            VarBind(OID('1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1'), Integer(10)),
            VarBind(OID('1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1'),
                    OctetString(b'More text')),
            VarBind(OID('1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1'),
                    OctetString(b'even more text')),
            VarBind(OID('1.3.6.1.2.1.4.1.0'), Integer(1)),
            VarBind(OID('1.3.6.1.2.1.4.3.0'), Integer(57)),
        ]))
        result = snmp.bulkget('192.168.1.1', 'private',
                              scalar_oids=['1.3.6.1.2.1.1.1.0'],
                              repeating_oids=[
                                  '1.3.6.1.2.1.3.1.1',
                                  '1.3.6.1.2.1.4',
                              ],
                              max_list_size=10,
                              port=161, timeout=1)

        expected = snmp.BulkResult(
            {'1.3.6.1.2.1.1.1.0': b'Some Text'},
            OrderedDict([
                ('1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1', 10),
                ('1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1', b'More text'),
                ('1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1', b'even more text'),
                ('1.3.6.1.2.1.4.1.0', 1),
                ('1.3.6.1.2.1.4.3.0', 57)
            ])
        )
        self.assertEqual(result, expected)
        self._send.assert_called()

    def test_bulkwalk(self):
        self._send.return_value = self._create_response_pdu(GetResponse(request_id=1, varbinds=[
            VarBind(OID('1.2.3.4.0'), Integer(10)),
            VarBind(OID('1.2.3.4.1'), OctetString(b'More text')),
            VarBind(OID('1.2.3.4.2'), OctetString(b'even more text')),
            VarBind(OID('2.2.2.2.2'), OctetString(b'End-Of-Walk')),
        ]))
        result = list(snmp.bulkwalk('192.168.1.1', 'private', ['1.2.3.4']))
        expected = [
            VarBind(OID('1.2.3.4.0'), 10),
            VarBind(OID('1.2.3.4.1'), b'More text'),
            VarBind(OID('1.2.3.4.2'), b'even more text'),
        ]
        self.assertEqual(result, expected)
        self._send.assert_called()

    def test_multigetnext(self):
        self._send.return_value = self._create_response_pdu(GetResponse(request_id=1, varbinds=[
            VarBind(ObjectIdentifier(1, 2, 3, 0), Integer(10)),
            VarBind(ObjectIdentifier(1, 2, 4, 0), Integer(11)),
        ]))
        result = snmp.multigetnext('192.168.1.1', 'private',
                                   ['1.2.3', '1.2.4'])
        expected = [
            VarBind(ObjectIdentifier(1, 2, 3, 0), 10),
            VarBind(ObjectIdentifier(1, 2, 4, 0), 11)
        ]
        self.assertEqual(result, expected)
        self._send.assert_called()

    def test_multiset(self):
        self._send.return_value = self._create_response_pdu(GetResponse(request_id=1, varbinds=[
            VarBind(OID('1.2.3'), OctetString(b'foo')),
            VarBind(OID('2.3.4'), OctetString(b'bar')),
        ]))
        result = snmp.multiset('127.0.0.1', 'private', [
            ('1.2.3', OctetString(b'foo')),
            ('2.3.4', OctetString(b'bar'))
        ])
        expected = {
            '1.2.3': b'foo',
            '2.3.4': b'bar'
        }
        self.assertEqual(result, expected)
        self._send.assert_called()

    def test_multiwalk(self):
        response_1 = readbytes('apiv1/multiwalk_response_1.hex')
        response_2 = readbytes('apiv1/multiwalk_response_2.hex')
        response_3 = readbytes('apiv1/multiwalk_response_3.hex')

        self._send.side_effect = [
            response_1,
            response_2,
            response_3,
        ]
        result = snmp.multiwalk('127.0.0.1', 'private', [
            '1.3.6.1.2.1.2.2.1.1',
            '1.3.6.1.2.1.1.2.1',
        ])
        expected = [
            VarBind(OID('1.3.6.1.2.1.2.2.1.1.1'), 1),
            VarBind(OID('1.3.6.1.2.1.2.2.1.1.6'), 6),
        ]
        result = list(result)
        self.assertEqual(result, expected)

    def test_set(self):
        self._send.return_value = readbytes('apiv1/set_response.hex')
        result = snmp.set(
            '127.0.0.1',
            'private',
            '1.3.6.1.2.1.1.6.0',
            OctetString(b'Hello')
        )
        self.assertEqual(result, b'On the move')
        self._send.assert_called()

    def test_table(self):
        responses = readbytes_multiple('apiv1/table_response.hex')
        self._send.side_effect = responses
        result = snmp.table('127.0.0.1', 'private', '1.3.6.1.2.1.2.2.1')
        expected = [{
            '0': '1',
            '1': 1,
            '10': 172,
            '11': 2,
            '12': 0,
            '13': 0,
            '14': 0,
            '15': 0,
            '16': 172,
            '17': 2,
            '18': 0,
            '19': 0,
            '2': b'lo',
            '20': 0,
            '21': 0,
            '22': '0.0',
            '3': 24,
            '4': 65536,
            '5': 10000000,
            '6': b'',
            '7': 1,
            '8': 1,
            '9': datetime.timedelta(0)
        }, {
            '0': '12',
            '1': 12,
            '10': 13952,
            '11': 140,
            '12': 0,
            '13': 0,
            '14': 0,
            '15': 0,
            '16': 4391,
            '17': 51,
            '18': 0,
            '19': 0,
            '2': b'eth0',
            '20': 0,
            '21': 0,
            '22': '0.0',
            '3': 6,
            '4': 1500,
            '5': 4294967295,
            '6': b'\x02B\xac\x11\x00\x02',
            '7': 1,
            '8': 1,
            '9': datetime.timedelta(0)
        }]
        self.assertCountEqual(result, expected)
        self.assertEqual(self._send.call_count, 45)

    def test_walk(self):
        responses = readbytes_multiple('apiv1/walk_response.hex')
        self._send.side_effect = responses
        result = snmp.walk('127.0.0.1', 'private', '1.3.6.1.2.1.2.2.1.1')
        result = list(result)
        expected = [
            VarBind(oid=OID('1.3.6.1.2.1.2.2.1.1.1'), value=1),
            VarBind(oid=OID('1.3.6.1.2.1.2.2.1.1.12'), value=12)
        ]
        self.assertCountEqual(result, expected)
        self.assertEqual(self._send.call_count, 3)
