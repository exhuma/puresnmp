# pylint: skip-file

"""
Test the "external" interface.

The "external" interface is what the user sees. It should be pythonic and easy
to use.
"""

from __future__ import unicode_literals

import sys
from datetime import timedelta

import pytest

from puresnmp.aio.api.pythonic import (
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
    walk
)
from puresnmp.const import Version
from puresnmp.exc import NoSuchOID, SnmpError
from puresnmp.pdu import BulkGetRequest, GetNextRequest, GetRequest, VarBind
from puresnmp.types import Counter, Gauge, IpAddress
from puresnmp.util import BulkResult
from puresnmp.x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
    to_bytes
)

from .asyncmock import AsyncGenMock, AsyncMock

try:
    from unittest.mock import patch, call
except ImportError:
    from mock import patch, call  # pip install mock


pytestmark = pytest.mark.skipif(sys.version_info < (3, 5),
                                reason="requires python3.5")


class TestGet(object):

    @pytest.mark.asyncio
    async def test_get_string(self):
        expected = (b'Linux d24cf7f36138 4.4.0-28-generic #47-Ubuntu SMP '
                    b'Fri Jun 24 10:09:13 UTC 2016 x86_64')
        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncMock) as mck:
            mck.get.return_value = OctetString(
                b'Linux d24cf7f36138 4.4.0-28-generic #47-Ubuntu SMP '
                b'Fri Jun 24 10:09:13 UTC 2016 x86_64')
            result = await get('::1', 'private', '1.2.3')
        assert result == expected

    @pytest.mark.asyncio
    async def test_get_oid(self):
        expected = ('1.3.6.1.4.1.8072.3.2.10')
        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncMock) as mck:
            mck.get.return_value = ObjectIdentifier.from_string(
                '1.3.6.1.4.1.8072.3.2.10')
            result = await get('::1', 'private', '1.2.3')
        assert result == expected


class TestSet(object):

    @pytest.mark.asyncio
    async def test_set_string(self):
        expected = (b'foo')
        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncMock) as mck:
            mck.multiset.return_value = {
                ObjectIdentifier.from_string('1.2.3'): OctetString(b'foo')
            }
            result = await set('::1', 'private', '1.2.3', OctetString(b'foo'))
        assert result == expected

    @pytest.mark.asyncio
    async def test_set_string_absolute(self):
        expected = (b'foo')
        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncMock) as mck:
            mck.multiset.return_value = {
                ObjectIdentifier.from_string('1.2.3'): OctetString(b'foo')
            }
            result = await set('::1', 'private', '.1.2.3', OctetString(b'foo'))
        assert result == expected


class TestWalk(object):

    @pytest.mark.asyncio
    @pytest.mark.skipif(sys.version_info < (3, 6),
                        reason="requires python3.6")
    async def test_walk(self):
        expected = [VarBind(
            '1.3.6.1.2.1.2.2.1.5.1', 10000000
        ), VarBind(
            '1.3.6.1.2.1.2.2.1.5.13', 4294967295
        )]

        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncGenMock) as mck:
            mck.walk.return_value = [
                VarBind(
                    ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.5.1'),
                    Gauge(10000000)
                ), VarBind(
                    ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.5.13'),
                    Integer(4294967295)
                )]
            result = []
            async for x in walk('::1', 'public', '1.3.6.1.2.1.2.2.1.5'):
                result.append(x)
        assert result == expected


class TestMultiGet(object):

    @pytest.mark.asyncio
    async def test_multiget(self):
        expected = ['1.3.6.1.4.1.8072.3.2.10',
                    b"Linux 7fbf2f0c363d 4.4.0-28-generic #47-Ubuntu SMP Fri "
                    b"Jun 24 10:09:13 UTC 2016 x86_64"]
        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncMock) as mck:
            mck.multiget.return_value = [
                ObjectIdentifier.from_string('1.3.6.1.4.1.8072.3.2.10'),
                OctetString(b"Linux 7fbf2f0c363d 4.4.0-28-generic "
                            b"#47-Ubuntu SMP Fri Jun 24 10:09:13 "
                            b"UTC 2016 x86_64")
            ]
            result = await multiget('::1', 'private', [
                '1.3.6.1.2.1.1.2.0',
                '1.3.6.1.2.1.1.1.0',
            ])
        assert result == expected


class TestMultiWalk(object):

    @pytest.mark.asyncio
    @pytest.mark.skipif(sys.version_info < (3, 6),
                        reason="requires python3.6")
    async def test_multi_walk(self):
        expected = [
            VarBind('1.3.6.1.2.1.2.2.1.1.1', 1),
            VarBind('1.3.6.1.2.1.2.2.1.2.1', b'lo'),
            VarBind('1.3.6.1.2.1.2.2.1.1.78', 78),
            VarBind('1.3.6.1.2.1.2.2.1.2.78', b'eth0')
        ]

        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncGenMock) as mck:
            mck.multiwalk.return_value = [VarBind(
                ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.1.1'),
                1
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
            result = []
            async for x in multiwalk('::1', 'public', [
                '1.3.6.1.2.1.2.2.1.1',
                '1.3.6.1.2.1.2.2.1.2'
            ]):
                result.append(x)
        # TODO (advanced): should order matter in the following result?
        assert len(result) == len(expected)


class TestMultiSet(object):

    @pytest.mark.asyncio
    async def test_multiset(self):
        """
        Test setting multiple OIDs at once.

        NOTE: The OID '1.3.6.1.2.1.1.5.0' below is manually edited for
              unit-testing. It probably has a different type in the real world!
        """
        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncMock) as mck:
            mck.multiset.return_value = {
                '1.3.6.1.2.1.1.4.0': OctetString(b'hello@world.com'),
                '1.3.6.1.2.1.1.5.0': OctetString(b'hello@world.com'),
            }
            result = await multiset('::1', 'private', [
                ('1.3.6.1.2.1.1.4.0', OctetString(b'hello@world.com')),
                ('1.3.6.1.2.1.1.5.0', OctetString(b'hello@world.com')),
            ])
        expected = {
            '1.3.6.1.2.1.1.4.0': b'hello@world.com',
            '1.3.6.1.2.1.1.5.0': b'hello@world.com',
        }
        assert result == expected

    @pytest.mark.asyncio
    async def test_multiset_absolute(self):
        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncMock) as mck:
            mck.multiset.return_value = {
                '1.3.6.1.2.1.1.4.0': OctetString(b'hello@world.com'),
                '1.3.6.1.2.1.1.5.0': OctetString(b'hello@world.com'),
            }
            result = await multiset('::1', 'private', [
                ('.1.3.6.1.2.1.1.4.0', OctetString(b'hello@world.com')),
                ('.1.3.6.1.2.1.1.5.0', OctetString(b'hello@world.com')),
            ])
        expected = {
            '1.3.6.1.2.1.1.4.0': b'hello@world.com',
            '1.3.6.1.2.1.1.5.0': b'hello@world.com',
        }
        assert result == expected


class TestGetNext(object):

    @pytest.mark.asyncio
    async def test_getnext(self):
        expected = VarBind('1.3.6.1.6.3.1.1.6.1.0', 354522558)

        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncMock) as mck:
            mck.multigetnext.return_value = [
                VarBind('1.3.6.1.6.3.1.1.6.1.0', Integer(354522558))
            ]
            result = await getnext('::1', 'private', '1.3.6.1.5')
        assert result == expected


class TestGetBulkGet(object):

    @pytest.mark.asyncio
    async def test_bulkget(self):
        expected = BulkResult(
            {'1.3.6.1.2.1.1.1.0': b'Linux 7e68e60fe303 4.4.0-28-generic '
             b'#47-Ubuntu SMP Fri Jun 24 10:09:13 UTC 2016 x86_64'},
            {'1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1': 10,
             '1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1': b'\x02B\xe2\xc5\x8d\t',
             '1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1': b'\xac\x11\x00\x01',
             '1.3.6.1.2.1.4.1.0': 1,
             '1.3.6.1.2.1.4.3.0': 57})

        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncMock) as mck:
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
            result = await bulkget('::1', 'public',
                                   ['1.3.6.1.2.1.1.1'],
                                   ['1.3.6.1.2.1.3.1'],
                                   max_list_size=5)
        assert result == expected


class TestGetBulkWalk(object):

    @pytest.mark.asyncio
    @pytest.mark.skipif(sys.version_info < (3, 6),
                        reason="requires python3.6")
    async def test_bulkwalk(self):
        request_ids = [1001613222, 1001613223, 1001613224]
        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncGenMock) as mck:
            mck.multiwalk.return_value = [
                VarBind('1.3.6.1.2.1.2.2.1.1.1', Integer(1)),
                VarBind('1.3.6.1.2.1.2.2.1.1.10', Integer(10)),
                VarBind('1.3.6.1.2.1.2.2.1.2.1', OctetString(b"lo")),
                VarBind('1.3.6.1.2.1.2.2.1.22.10', ObjectIdentifier(0, 0))
            ]

            result = []
            async for x in bulkwalk('127.0.0.1', 'private', ['1.3.6.1.2.1.2.2'],
                                    bulk_size=20):
                result.append(x)

        expected = [
            VarBind('1.3.6.1.2.1.2.2.1.1.1', 1),
            VarBind('1.3.6.1.2.1.2.2.1.1.10', 10),
            VarBind('1.3.6.1.2.1.2.2.1.2.1', b"lo"),
            VarBind('1.3.6.1.2.1.2.2.1.22.10', '0.0'),
        ]

        assert result == expected


class TestTable(object):

    @pytest.mark.asyncio
    @pytest.mark.skipif(sys.version_info < (3, 6),
                        reason="requires python3.6")
    async def test_table(self):
        with patch('puresnmp.aio.api.pythonic.raw', new_callable=AsyncGenMock) as mck:
            oid = ObjectIdentifier.from_string
            mck.table.return_value = [
                {'0': '1', '1': Integer(1)},
                {'0': '2', '1': Integer(2)},
            ]
            aio_result = table('1.2.3.4', 'private', '1.2')
            result = []
            async for row in aio_result:
                result.append(row)
        expected = [
            {'0': '1', '1': 1},
            {'0': '2', '1': 2},
        ]
        assert len(result) == len(expected)


class TestBulkTable(object):

    @pytest.mark.asyncio
    @pytest.mark.skipif(sys.version_info < (3, 6),
                        reason="requires python3.6")
    async def test_table(self):
        with patch('puresnmp.aio.api.pythonic.raw') as mck:
            oid = ObjectIdentifier.from_string
            mck.bulktable.return_value = [
                {'0': '1', '1': Integer(1)},
                {'0': '2', '1': Integer(2)},
            ]
            aio_result = bulktable('1.2.3.4', 'private', '1.2')
            result = []
            async for row in aio_result:
                result.append(row)
        expected = [
            {'0': '1', '1': 1},
            {'0': '2', '1': 2},
        ]
        assert result == expected
