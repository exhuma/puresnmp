# pylint: skip-file

"""
Test the "external" interface.

The "external" interface is what the user sees. It should be pythonic and easy
to use.
"""

from __future__ import unicode_literals

import unittest
from datetime import timedelta
from ipaddress import ip_address

import six

from puresnmp.api.pythonic import (
    bulkget,
    bulktable,
    bulkwalk,
    get,
    getnext,
    multiget,
    multiset,
    multiwalk,
    set,
    table,
    traps,
    walk
)
from puresnmp.const import Version
from puresnmp.exc import NoSuchOID, SnmpError
from puresnmp.pdu import (
    BulkGetRequest,
    GetNextRequest,
    GetRequest,
    Trap,
    VarBind
)
from puresnmp.types import Counter, Gauge, IpAddress
from puresnmp.typevars import SocketInfo
from puresnmp.util import BulkResult
from puresnmp.x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
    to_bytes
)

from . import ByteTester

try:
    from unittest.mock import patch, call
except ImportError:
    from mock import patch, call  # pip install mock


class TestGet(ByteTester):

    def test_get_string(self):
        expected = (b'Linux d24cf7f36138 4.4.0-28-generic #47-Ubuntu SMP '
                    b'Fri Jun 24 10:09:13 UTC 2016 x86_64')
        with patch('puresnmp.api.pythonic.raw') as mck:
            mck.get.return_value = OctetString(
                b'Linux d24cf7f36138 4.4.0-28-generic #47-Ubuntu SMP '
                b'Fri Jun 24 10:09:13 UTC 2016 x86_64')
            result = get('::1', 'private', '1.2.3')
        self.assertEqual(result, expected)

    def test_get_oid(self):
        expected = ('1.3.6.1.4.1.8072.3.2.10')
        with patch('puresnmp.api.pythonic.raw') as mck:
            mck.get.return_value = ObjectIdentifier.from_string(
                '1.3.6.1.4.1.8072.3.2.10')
            result = get('::1', 'private', '1.2.3')
        self.assertEqual(result, expected)


class TestSet(ByteTester):

    def test_set_string(self):
        expected = (b'foo')
        with patch('puresnmp.api.pythonic.raw') as mck:
            mck.multiset.return_value = {
                ObjectIdentifier.from_string('1.2.3'): OctetString(b'foo')
            }
            result = set('::1', 'private', '1.2.3', OctetString(b'foo'))
        self.assertEqual(result, expected)

    def test_set_string_absolute(self):
        expected = (b'foo')
        with patch('puresnmp.api.pythonic.raw') as mck:
            mck.multiset.return_value = {
                ObjectIdentifier.from_string('1.2.3'): OctetString(b'foo')
            }
            result = set('::1', 'private', '.1.2.3', OctetString(b'foo'))
        self.assertEqual(result, expected)


class TestWalk(unittest.TestCase):

    def test_walk(self):
        expected = [VarBind(
            '1.3.6.1.2.1.2.2.1.5.1', 10000000
        ), VarBind(
            '1.3.6.1.2.1.2.2.1.5.13', 4294967295
        )]

        with patch('puresnmp.api.pythonic.raw') as mck:
            mck.walk.return_value = [
                VarBind(
                    ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.5.1'),
                    Gauge(10000000)
                ), VarBind(
                    ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.5.13'),
                    Integer(4294967295)
                )]
            result = list(walk('::1', 'public', '1.3.6.1.2.1.2.2.1.5'))
        self.assertEqual(result, expected)


class TestMultiGet(unittest.TestCase):

    def test_multiget(self):
        expected = ['1.3.6.1.4.1.8072.3.2.10',
                    b"Linux 7fbf2f0c363d 4.4.0-28-generic #47-Ubuntu SMP Fri "
                    b"Jun 24 10:09:13 UTC 2016 x86_64"]
        with patch('puresnmp.api.pythonic.raw') as mck:
            mck.multiget.return_value = [
                ObjectIdentifier.from_string('1.3.6.1.4.1.8072.3.2.10'),
                OctetString(b"Linux 7fbf2f0c363d 4.4.0-28-generic "
                            b"#47-Ubuntu SMP Fri Jun 24 10:09:13 "
                            b"UTC 2016 x86_64")
            ]
            result = multiget('::1', 'private', [
                '1.3.6.1.2.1.1.2.0',
                '1.3.6.1.2.1.1.1.0',
            ])
        self.assertEqual(result, expected)


class TestMultiWalk(unittest.TestCase):

    def test_multi_walk(self):
        expected = [
            VarBind('1.3.6.1.2.1.2.2.1.1.1', 1),
            VarBind('1.3.6.1.2.1.2.2.1.2.1', b'lo'),
            VarBind('1.3.6.1.2.1.2.2.1.1.78', 78),
            VarBind('1.3.6.1.2.1.2.2.1.2.78', b'eth0')
        ]

        with patch('puresnmp.api.pythonic.raw') as mck:
            mck.multiwalk.return_value = [VarBind(
                ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.1.1'),
                1,
            ), VarBind(
                ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.2.1'),
                b'lo'
            ), VarBind(
                ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.1.78'),
                78
            ), VarBind(
                ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.2.78'),
                b'eth0'
            )]
            result = list(multiwalk('::1', 'public', [
                '1.3.6.1.2.1.2.2.1.1',
                '1.3.6.1.2.1.2.2.1.2'
            ]))
        # TODO (advanced): should order matter in the following result?
        six.assertCountEqual(self, result, expected)


class TestMultiSet(unittest.TestCase):

    def test_multiset(self):
        """
        Test setting multiple OIDs at once.

        NOTE: The OID '1.3.6.1.2.1.1.5.0' below is manually edited for
              unit-testing. It probably has a different type in the real world!
        """
        with patch('puresnmp.api.pythonic.raw') as mck:
            mck.multiset.return_value = {
                '1.3.6.1.2.1.1.4.0': OctetString(b'hello@world.com'),
                '1.3.6.1.2.1.1.5.0': OctetString(b'hello@world.com'),
            }
            result = multiset('::1', 'private', [
                ('1.3.6.1.2.1.1.4.0', OctetString(b'hello@world.com')),
                ('1.3.6.1.2.1.1.5.0', OctetString(b'hello@world.com')),
            ])
        expected = {
            '1.3.6.1.2.1.1.4.0': b'hello@world.com',
            '1.3.6.1.2.1.1.5.0': b'hello@world.com',
        }
        self.assertEqual(result, expected)

    def test_multiset_absolute(self):
        with patch('puresnmp.api.pythonic.raw') as mck:
            mck.multiset.return_value = {
                '1.3.6.1.2.1.1.4.0': OctetString(b'hello@world.com'),
                '1.3.6.1.2.1.1.5.0': OctetString(b'hello@world.com'),
            }
            result = multiset('::1', 'private', [
                ('.1.3.6.1.2.1.1.4.0', OctetString(b'hello@world.com')),
                ('.1.3.6.1.2.1.1.5.0', OctetString(b'hello@world.com')),
            ])
        expected = {
            '1.3.6.1.2.1.1.4.0': b'hello@world.com',
            '1.3.6.1.2.1.1.5.0': b'hello@world.com',
        }
        self.assertEqual(result, expected)


class TestGetNext(unittest.TestCase):

    def test_getnext(self):
        expected = VarBind('1.3.6.1.6.3.1.1.6.1.0', 354522558)

        with patch('puresnmp.api.pythonic.raw') as mck:
            mck.multigetnext.return_value = [
                VarBind('1.3.6.1.6.3.1.1.6.1.0', Integer(354522558))
            ]
            result = getnext('::1', 'private', '1.3.6.1.5')
        self.assertEqual(result, expected)


class TestGetBulkGet(unittest.TestCase):

    def test_bulkget(self):
        expected = BulkResult(
            {'1.3.6.1.2.1.1.1.0': b'Linux 7e68e60fe303 4.4.0-28-generic '
             b'#47-Ubuntu SMP Fri Jun 24 10:09:13 UTC 2016 x86_64'},
            {'1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1': 10,
             '1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1': b'\x02B\xe2\xc5\x8d\t',
             '1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1': b'\xac\x11\x00\x01',
             '1.3.6.1.2.1.4.1.0': 1,
             '1.3.6.1.2.1.4.3.0': 57})

        with patch('puresnmp.api.pythonic.raw') as mck:
            mck.bulkget.return_value = BulkResult({
                '1.3.6.1.2.1.1.1.0': OctetString(
                    b'Linux 7e68e60fe303 4.4.0-28-generic '
                    b'#47-Ubuntu SMP Fri Jun 24 10:09:13 UTC 2016 x86_64')
            }, {
                '1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1': Integer(10),
                '1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1': OctetString(
                    b'\x02B\xe2\xc5\x8d\t'),
                '1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1': IpAddress(
                    b'\xac\x11\x00\x01'),
                '1.3.6.1.2.1.4.1.0': Integer(1),
                '1.3.6.1.2.1.4.3.0': Counter(57)
            })
            result = bulkget('::1', 'public',
                             ['1.3.6.1.2.1.1.1'],
                             ['1.3.6.1.2.1.3.1'],
                             max_list_size=5)
        self.assertEqual(result, expected)


class TestGetBulkWalk(unittest.TestCase):

    def test_bulkwalk(self):
        request_ids = [1001613222, 1001613223, 1001613224]
        with patch('puresnmp.api.pythonic.raw') as mck:
            mck.multiwalk.return_value = [
                VarBind('1.3.6.1.2.1.2.2.1.1.1', Integer(1)),
                VarBind('1.3.6.1.2.1.2.2.1.1.10', Integer(10)),
                VarBind('1.3.6.1.2.1.2.2.1.2.1', OctetString(b"lo")),
                VarBind('1.3.6.1.2.1.2.2.1.22.10', ObjectIdentifier(0, 0))
            ]

            result = list(bulkwalk('127.0.0.1', 'private', ['1.3.6.1.2.1.2.2'],
                                   bulk_size=20))

        expected = [
            VarBind('1.3.6.1.2.1.2.2.1.1.1', 1),
            VarBind('1.3.6.1.2.1.2.2.1.1.10', 10),
            VarBind('1.3.6.1.2.1.2.2.1.2.1', b"lo"),
            VarBind('1.3.6.1.2.1.2.2.1.22.10', '0.0'),
        ]

        self.assertEqual(result, expected)


class TestTable(unittest.TestCase):

    def test_table(self):
        with patch('puresnmp.api.pythonic.raw') as mck:
            oid = ObjectIdentifier.from_string
            mck.table.return_value = [
                {'0': '1', '1': Integer(1)},
                {'0': '2', '1': Integer(2)},
            ]
            result = list(table('1.2.3.4', 'private', '1.2'))
        expected = [
            {'0': '1', '1': 1},
            {'0': '2', '1': 2},
        ]
        six.assertCountEqual(self, result, expected)


class TestBulkTable(unittest.TestCase):

    def test_bulktable(self):
        with patch('puresnmp.api.pythonic.raw') as mck:
            oid = ObjectIdentifier.from_string
            mck.bulktable.return_value = [
                {'0': '1', '1': Integer(1)},
                {'0': '2', '1': Integer(2)},
            ]
            result = list(bulktable('1.2.3.4', 'private', '1.2'))
        expected = [
            {'0': '1', '1': 1},
            {'0': '2', '1': 2},
        ]
        six.assertCountEqual(self, result, expected)


class TestTraps(unittest.TestCase):

    def test_traps(self):
        with patch('puresnmp.api.pythonic.raw') as mck:
            oid = ObjectIdentifier.from_string
            mck.traps.return_value = [Trap(
                request_id=1,
                error_status=0,
                error_index=0,
                varbinds=[
                    VarBind(oid('1.2.1.1'), OctetString(b'fake-uptime')),
                    VarBind(oid('1.2.1.2'), ObjectIdentifier(1, 2, 3, 4)),
                    VarBind(oid('1.2.1.3'), Integer(13)),
                    VarBind(oid('1.2.1.4'), OctetString(b'fake-value-2')),
                ]
            )]
            result = []
            for trap in traps():
                result.append((trap.uptime, trap.oid, trap.values))
        expected = [(
            b'fake-uptime',
            u'1.2.3.4',
            {
                u'1.2.1.3': 13,
                u'1.2.1.4': b'fake-value-2',
            }
        )]
        self.assertEqual(result, expected)

    def test_trap_origins(self):
        """
        We want to be able to see where a trap was sent from
        """
        with patch("puresnmp.api.pythonic.raw") as mck:
            oid = ObjectIdentifier.from_string
            mck.traps.return_value = [
                Trap(request_id=1, error_status=0, error_index=0, varbinds=[])
            ]
            mck.traps.return_value[-1].source = SocketInfo("192.0.2.1", 64001)
            result = []
            for trap in traps():
                result.append(trap.origin)
        expected = ["192.0.2.1"]
        self.assertEqual(result, expected)
