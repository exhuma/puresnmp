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

    def test_get(self):
        response = readbytes('apiv1/get_response.hex')
        self._send.return_value = response
        result = snmp.get('192.168.1.1', 'private', '1.3.6.1.2.1.1.2.0')
        self.assertEqual(result, '1.3.6.1.4.1.8072.3.2.10')
        self._send.assert_called()

    def test_multiget(self):
        response = readbytes('apiv1/multiget_response.hex')
        self._send.return_value = response
        oids = ['1.3.6.1.2.1.1.4.0', '1.3.6.1.2.1.1.6.0']
        result = snmp.multiget('192.168.1.1', 'private', oids,
                               port=161, timeout=1)
        self.assertEqual(result, [b'root', b'On the move'])
        self._send.assert_called()

    def test_getnext(self):
        response = readbytes('apiv1/getnext_response.hex')
        self._send.return_value = response
        result = snmp.getnext('192.168.1.1', 'private', '1.3.6.1.2.1.1.6.0',
                              port=161, timeout=1)
        expected = VarBind(OID('1.3.6.1.2.1.1.7.0'), 72)
        self.assertEqual(result, expected)
        self._send.assert_called()

    def test_bulkget(self):
        response = readbytes('apiv1/bulkget_response.hex')
        self._send.return_value = response
        result = snmp.bulkget('192.168.1.1', 'private',
                              scalar_oids=['1.3.6.1.2.1.1.1.0'],
                              repeating_oids=[
                                  '1.3.6.1.2.1.3.1.1',
                                  '1.3.6.1.2.1.4',
                              ],
                              max_list_size=10,
                              port=161, timeout=1)

        expected = snmp.BulkResult(
            {'1.3.6.1.2.1.1.2.0': '1.3.6.1.4.1.8072.3.2.10'},
            OrderedDict([
                ('1.3.6.1.2.1.3.1.1.1.12.1.172.17.0.1', 12),
                ('1.3.6.1.2.1.4.1.0', 1),
                ('1.3.6.1.2.1.3.1.1.2.12.1.172.17.0.1', b'\x02B@j\xbf\xcd'),
                ('1.3.6.1.2.1.4.2.0', 64),
                ('1.3.6.1.2.1.3.1.1.3.12.1.172.17.0.1', b'\xac\x11\x00\x01'),
                ('1.3.6.1.2.1.4.3.0', 589),
                ('1.3.6.1.2.1.4.4.0', 0),
                ('1.3.6.1.2.1.4.5.0', 0),
                ('1.3.6.1.2.1.4.6.0', 0),
                ('1.3.6.1.2.1.4.7.0', 0),
                ('1.3.6.1.2.1.4.8.0', 0),
                ('1.3.6.1.2.1.4.9.0', 410),
                ('1.3.6.1.2.1.4.10.0', 409)
            ])
        )
        self.assertEqual(result, expected)
        self._send.assert_called()

    def test_bulkwalk(self):
        response = readbytes_multiple('apiv1/bulkwalk_response.hex')
        self._send.side_effect = response
        result = list(snmp.bulkwalk('192.168.1.1', 'private', [
            '1.3.6.1.2.1.1.9.1.4']))

        expected = [
            VarBind(OID('1.3.6.1.2.1.1.9.1.4.1'), datetime.timedelta(0)),
            VarBind(OID('1.3.6.1.2.1.1.9.1.4.2'), datetime.timedelta(0)),
            VarBind(OID('1.3.6.1.2.1.1.9.1.4.3'), datetime.timedelta(0)),
            VarBind(OID('1.3.6.1.2.1.1.9.1.4.4'), datetime.timedelta(0)),
            VarBind(OID('1.3.6.1.2.1.1.9.1.4.5'), datetime.timedelta(0)),
            VarBind(OID('1.3.6.1.2.1.1.9.1.4.6'), datetime.timedelta(0)),
            VarBind(OID('1.3.6.1.2.1.1.9.1.4.7'), datetime.timedelta(0)),
            VarBind(OID('1.3.6.1.2.1.1.9.1.4.8'), datetime.timedelta(0)),
            VarBind(OID('1.3.6.1.2.1.1.9.1.4.9'), datetime.timedelta(0)),
            VarBind(OID('1.3.6.1.2.1.1.9.1.4.10'), datetime.timedelta(0))
        ]

        self.assertEqual(result, expected)
        self._send.assert_called()

    def test_multigetnext(self):
        response = readbytes('apiv1/multigetnext_response.hex')
        self._send.return_value = response
        result = snmp.multigetnext('192.168.1.1', 'private',
                                   ['1.3.6.1.2.1.3.1.1', '1.3.6.1.2.1.4'])
        expected = [
            VarBind(OID('1.3.6.1.2.1.3.1.1.1.12.1.172.17.0.1'), 12),
            VarBind(OID('1.3.6.1.2.1.4.1.0'), 1)
        ]
        self.assertEqual(result, expected)
        self._send.assert_called()

    def test_multiset(self):
        response = readbytes('apiv1/multiset_response.hex')
        self._send.return_value = response
        result = snmp.multiset('127.0.0.1', 'private', [
            ('1.3.6.1.2.1.1.4.0', OctetString(b'foo')),
            ('1.3.6.1.2.1.1.6.0', OctetString(b'bar'))
        ])
        expected = {
            '1.3.6.1.2.1.1.4.0': b'foo',
            '1.3.6.1.2.1.1.6.0': b'bar'
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
