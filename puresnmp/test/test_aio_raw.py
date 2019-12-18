# pylint: skip-file

"""
Test the external "raw" interface.

"raw" means that types are not converted to pythonic types but are returned as
PureSNMP object instances.
"""

import sys
from datetime import timedelta
from unittest import skipUnless

import pytest

from puresnmp.aio.api.raw import (
    bulkget,
    bulktable,
    bulkwalk,
    get,
    getnext,
    multiget,
    multiset,
    multiwalk,
    set,
    walk
)
from puresnmp.const import Version
from puresnmp.exc import NoSuchOID, SnmpError
from puresnmp.pdu import BulkGetRequest, GetNextRequest, GetRequest, VarBind
from puresnmp.types import Counter, Gauge, IpAddress, TimeTicks
from puresnmp.util import BulkResult
from puresnmp.x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
    to_bytes
)

from . import readbytes, readbytes_multiple
from .asyncmock import AsyncMock

try:
    from unittest.mock import patch, call
except ImportError:
    from mock import patch, call  # type: ignore

pytestmark = pytest.mark.skipif(sys.version_info < (3, 5),
                                reason="requires python3.5")


class TestGet(object):

    @pytest.mark.asyncio
    async def test_get_string(self):
        data = readbytes('get_sysdescr_01.hex')
        expected = OctetString(
            b'Linux d24cf7f36138 4.4.0-28-generic #47-Ubuntu SMP '
            b'Fri Jun 24 10:09:13 UTC 2016 x86_64')
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            result = await get('::1', 'private', '1.2.3')
        assert result == expected

    @pytest.mark.asyncio
    async def test_get_oid(self):
        data = readbytes('get_sysoid_01.hex')
        expected = ObjectIdentifier.from_string('1.3.6.1.4.1.8072.3.2.10')
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            result = await get('::1', 'private', '1.2.3')
        assert result == expected

    @pytest.mark.asyncio
    async def test_get_multiple_return_binds(self):
        """
        A "GET" response should only return one varbind.
        """
        data = readbytes('get_sysoid_01_error.hex')
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            with pytest.raises(SnmpError, match='varbind'):
                await get('::1', 'private', '1.2.3')

    @pytest.mark.asyncio
    async def test_get_non_existing_oid(self):
        """
        A "GET" response on a non-existing OID should raise an appropriate
        exception.
        """
        data = readbytes('get_non_existing.hex')
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            with pytest.raises(NoSuchOID):
                await get('::1', 'private', '1.2.3')


class TestWalk(object):

    @pytest.mark.asyncio
    async def test_walk(self):
        response_1 = readbytes('walk_response_1.hex')
        response_2 = readbytes('walk_response_2.hex')
        response_3 = readbytes('walk_response_3.hex')

        expected = [VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.5.1'),
            Gauge(10000000)
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.5.13'),
            Gauge(4294967295)
        )]

        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().send.side_effect = [response_1, response_2, response_3]
            mck().get_request_id.return_value = 0
            result = []
            async for x in walk('::1', 'public', '1.3.6.1.2.1.2.2.1.5'):
                result.append(x)
        assert result == expected

    @pytest.mark.asyncio
    async def test_walk_multiple_return_binds(self):
        """
        A "WALK" response should only return one varbind.
        """
        data = readbytes('get_sysoid_01_error.hex')
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            with pytest.raises(SnmpError, match='varbind'):
                async for x in walk('::1', 'private', '1.2.3'):
                    pass


class TestBulkTable(object):

    @pytest.mark.asyncio
    async def test_bulktable(self):
        responses = readbytes_multiple('bulktable_response.hex')

        expected = [{
            '0': '1',
            '1': Integer(1),
            '2': OctetString(b'lo'),
            '3': Integer(24),
            '4': Integer(65536),
            '5': Gauge(10000000),
            '6': OctetString(b''),
            '7': Integer(1),
            '8': Integer(1),
            '9': TimeTicks(0),
            '10': Counter(172),
            '11': Counter(2),
            '12': Counter(0),
            '13': Counter(0),
            '14': Counter(0),
            '15': Counter(0),
            '16': Counter(172),
            '17': Counter(2),
            '18': Counter(0),
            '19': Counter(0),
            '20': Counter(0),
            '21': Gauge(0),
            '22': ObjectIdentifier(0, 0),
        }, {
            '0': '4',
            '1': Integer(4),
            '2': OctetString(b'eth0'),
            '3': Integer(6),
            '4': Integer(1500),
            '5': Gauge(4294967295),
            '6': OctetString(b'\x02B\xac\x11\x00\x02'),
            '7': Integer(1),
            '8': Integer(1),
            '9': TimeTicks(0),
            '10': Counter(548760),
            '11': Counter(3888),
            '12': Counter(0),
            '13': Counter(0),
            '14': Counter(0),
            '15': Counter(0),
            '16': Counter(186660),
            '17': Counter(1875),
            '18': Counter(0),
            '19': Counter(0),
            '20': Counter(0),
            '21': Gauge(0),
            '22': ObjectIdentifier(0, 0),
        }]

        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().send.side_effect = responses
            mck().get_request_id.return_value = 0
            result = []
            table = await bulktable('127.0.0.1', 'private', '1.3.6.1.2.1.2.2')
            for row in table:
                result.append(row)
        assert sorted(result, key=lambda x: x['0']) == expected


class TestMultiGet(object):

    @pytest.mark.asyncio
    async def test_multiget(self):
        data = readbytes('multiget_response.hex')
        expected = [
            ObjectIdentifier.from_string('1.3.6.1.4.1.8072.3.2.10'),
            OctetString(b"Linux 7fbf2f0c363d 4.4.0-28-generic "
                        b"#47-Ubuntu SMP Fri Jun 24 10:09:13 "
                        b"UTC 2016 x86_64")
        ]
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().get_request_id.return_value = 0
            mck().send.return_value = data
            result = await multiget('::1', 'private', [
                '1.3.6.1.2.1.1.2.0',
                '1.3.6.1.2.1.1.1.0',
            ])
        assert result == expected


class TestMultiWalk(object):

    # TODO (advanced) figure out why this fails on Python 2!
    @skipUnless(
        sys.version_info >= (3, 0),
        "For some reason this fails on Python 2 and I don't know why")
    @pytest.mark.asyncio
    async def test_multi_walk(self):
        response_1 = readbytes('multiwalk_response_1.hex')
        response_2 = readbytes('multiwalk_response_2.hex')
        response_3 = readbytes('multiwalk_response_3.hex')

        expected = [VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.1.1'), Integer(1)
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.2.1'),
            OctetString(b'lo')
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.1.78'), Integer(78)
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.2.78'),
            OctetString(b'eth0')
        )]

        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().get_request_id.return_value = 0
            mck().send.side_effect = [response_1, response_2, response_3]
            result = []
            async for x in multiwalk('::1', 'public', [
                '1.3.6.1.2.1.2.2.1.1',
                '1.3.6.1.2.1.2.2.1.2'
            ]):
                result.append(x)
        # TODO (advanced): should order matter in the following result?
        assert len(result) == len(expected)

    @pytest.mark.asyncio
    async def test_eom(self):
        '''
        A test for a walk operation which runs into the endOfMibView marker
        '''

        data_generator = readbytes_multiple('x690/multiwalk_endofmibview.hex')

        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().get_request_id.return_value = 0
            mck().send.side_effect = data_generator
            result = []
            async for row in multiwalk('::1', 'public', [
                '1.3.6.1.6.3.16.1.5.2.1.6.6.95.110.111.110.101.95.1',
            ]):
                result.append(row)

        root = '1.3.6.1.6.3.16.1.5.2.1.6.6.95.110.111.110.101.95.1.'
        expected = [
            (root+'0', 1),
            (root+'1', 1),
            (root+'2', 1),
        ]

        simplified_result = [
            (str(oid), value.pythonize()) for oid, value in result
        ]

        assert simplified_result == expected


class TestMultiSet(object):

    @pytest.mark.asyncio
    async def test_multiset(self):
        """
        Test setting multiple OIDs at once.

        NOTE: The OID '1.3.6.1.2.1.1.5.0' below is manually edited for
              unit-testing. It probably has a different type in the real world!
        """
        data = readbytes('multiset_response.hex')
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().get_request_id.return_value = 0
            mck().send.return_value = data
            result = await multiset('::1', 'private', [
                ('1.3.6.1.2.1.1.4.0', OctetString(b'hello@world.com')),
                ('1.3.6.1.2.1.1.5.0', OctetString(b'hello@world.com')),
            ])
        expected = {
            '1.3.6.1.2.1.1.4.0': OctetString(b'hello@world.com'),
            '1.3.6.1.2.1.1.5.0': OctetString(b'hello@world.com'),
        }
        assert result == expected


class TestGetNext(object):

    @pytest.mark.asyncio
    async def test_get_call_args(self):
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            GetNextRequest(0, ObjectIdentifier(1, 2, 3))
        )
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().get_request_id.return_value = 0
            mck().send.return_value = data
            await getnext('::1', 'public', '1.2.3')
            mck.assert_called_with(timeout=6)
            mck().send.assert_called_with(
                '::1', 161, to_bytes(packet))

    @pytest.mark.asyncio
    async def test_getnext(self):
        data = readbytes('getnext_response.hex')
        expected = VarBind('1.3.6.1.6.3.1.1.6.1.0', Integer(354522558))

        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().get_request_id.return_value = 0
            mck().send.return_value = data
            result = await getnext('::1', 'private', '1.3.6.1.5')
        assert result == expected


class TestGetBulkGet(object):

    @pytest.mark.asyncio
    async def test_get_call_args(self):
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            BulkGetRequest(0, 1, 2,
                           ObjectIdentifier(1, 2, 3),
                           ObjectIdentifier(1, 2, 4))
        )
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().get_request_id.return_value = 0
            mck().send.return_value = data
            await bulkget('::1', 'public',
                          ['1.2.3'],
                          ['1.2.4'],
                          max_list_size=2)
            mck.assert_called_with(timeout=6)
            mck().send.assert_called_with('::1', 161, to_bytes(packet))

    @pytest.mark.asyncio
    async def test_bulkget(self):
        data = readbytes('bulk_get_response.hex')
        expected = BulkResult(
            {'1.3.6.1.2.1.1.1.0': OctetString(
                b'Linux 7e68e60fe303 4.4.0-28-generic '
                b'#47-Ubuntu SMP Fri Jun 24 10:09:13 UTC 2016 x86_64')},
            {'1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1': Integer(10),
             '1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1':
             OctetString(b'\x02B\xe2\xc5\x8d\t'),
             '1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1':
             IpAddress(b'\xac\x11\x00\x01'),
             '1.3.6.1.2.1.4.1.0': Integer(1),
             '1.3.6.1.2.1.4.3.0': Counter(57)})

        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().get_request_id.return_value = 0
            mck().send.return_value = data
            result = await bulkget('::1', 'public',
                                   ['1.3.6.1.2.1.1.1'],
                                   ['1.3.6.1.2.1.3.1'],
                                   max_list_size=5)
        assert result == expected

    @pytest.mark.asyncio
    async def test_eom(self):
        '''
        Test a bulg-get operation which runs into the "endOfMibView" marker.
        '''

        data = readbytes('x690/bulk_get_eom_response.hex')
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().get_request_id.return_value = 0
            mck().send.return_value = data
            result = await bulkget('::1', 'public', [], ['1.2.4'],
                                   max_list_size=10)

        expected_scalars = {}
        assert result.scalars == expected_scalars

        root = '1.3.6.1.6.3.16.1.5.2.1.6.6.95.110.111.110.101.95.1.'
        expected_listing = {
            root + '0': Integer(1),
            root + '1': Integer(1),
            root + '2': Integer(1),
        }
        assert result.listing == expected_listing


class TestGetBulkWalk(object):

    @pytest.mark.asyncio
    async def test_get_call_args(self):
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            BulkGetRequest(0, 0, 2, ObjectIdentifier(1, 2, 3))
        )
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().get_request_id.return_value = 0
            mck().send.return_value = data

            # we need to wrap this in a list to consume the generator.
            async for x in bulkwalk('::1', 'public',
                                    ['1.2.3'],
                                    bulk_size=2):
                pass
            mck.assert_called_with(timeout=6)
            mck().send.assert_called_with('::1', 161, to_bytes(packet))

    @pytest.mark.asyncio
    async def test_get_call_args_issue_22(self):
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            BulkGetRequest(0, 0, 2, ObjectIdentifier(1, 2, 3))
        )
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().send.return_value = data
            mck().get_request_id.return_value = 0

            with pytest.raises(TypeError, match=r'OIDS.*list'):
                # we need to wrap this in a list to consume the generator.
                async for x in bulkwalk('::1', 'public', '1.2.3', bulk_size=2):
                    pass

    @pytest.mark.asyncio
    async def test_bulkwalk(self):
        req1 = readbytes('bulkwalk_request_1.hex')
        req2 = readbytes('bulkwalk_request_2.hex')
        req3 = readbytes('bulkwalk_request_3.hex')

        responses = [
            readbytes('bulkwalk_response_1.hex'),
            readbytes('bulkwalk_response_2.hex'),
            readbytes('bulkwalk_response_3.hex'),
        ]
        with patch('puresnmp.aio.api.raw.Transport') as mck:
            mck().send = AsyncMock()
            mck().send.side_effect = responses

            request_ids = [1001613222, 1001613223, 1001613224]
            mck().get_request_id.side_effect = request_ids

            result = []
            async for x in bulkwalk('127.0.0.1', 'private', ['1.3.6.1.2.1.2.2'],
                                    bulk_size=20):
                result.append(x)

            mck.assert_called_with(timeout=6)
            assert mck().send.mock_calls == [
                call('127.0.0.1', 161, req1),
                call('127.0.0.1', 161, req2),
                call('127.0.0.1', 161, req3),
            ]

            expected = [
                VarBind('1.3.6.1.2.1.2.2.1.1.1', Integer(1)),
                VarBind('1.3.6.1.2.1.2.2.1.1.10', Integer(10)),
                VarBind('1.3.6.1.2.1.2.2.1.2.1', OctetString(b"lo")),
                VarBind('1.3.6.1.2.1.2.2.1.2.10', OctetString(b"eth0")),
                VarBind('1.3.6.1.2.1.2.2.1.3.1', Integer(24)),
                VarBind('1.3.6.1.2.1.2.2.1.3.10', Integer(6)),
                VarBind('1.3.6.1.2.1.2.2.1.4.1', Integer(65536)),
                VarBind('1.3.6.1.2.1.2.2.1.4.10', Integer(1500)),
                VarBind('1.3.6.1.2.1.2.2.1.5.1',  Gauge(10000000)),
                VarBind('1.3.6.1.2.1.2.2.1.5.10',  Gauge(4294967295)),
                VarBind('1.3.6.1.2.1.2.2.1.6.1', OctetString(b"")),
                VarBind('1.3.6.1.2.1.2.2.1.6.10',
                        OctetString(b"\x02\x42\xAC\x11\x00\x02")),
                VarBind('1.3.6.1.2.1.2.2.1.7.1', Integer(1)),
                VarBind('1.3.6.1.2.1.2.2.1.7.10', Integer(1)),
                VarBind('1.3.6.1.2.1.2.2.1.8.1', Integer(1)),
                VarBind('1.3.6.1.2.1.2.2.1.8.10', Integer(1)),
                VarBind('1.3.6.1.2.1.2.2.1.9.1', TimeTicks(0)),
                VarBind('1.3.6.1.2.1.2.2.1.9.10', TimeTicks(0)),
                VarBind('1.3.6.1.2.1.2.2.1.10.1', Counter(172)),
                VarBind('1.3.6.1.2.1.2.2.1.10.10', Counter(60558)),
                VarBind('1.3.6.1.2.1.2.2.1.11.1', Counter(2)),
                VarBind('1.3.6.1.2.1.2.2.1.11.10', Counter(564)),
                VarBind('1.3.6.1.2.1.2.2.1.12.1', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.12.10', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.13.1', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.13.10', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.14.1', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.14.10', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.15.1', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.15.10', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.16.1', Counter(172)),
                VarBind('1.3.6.1.2.1.2.2.1.16.10', Counter(44295)),
                VarBind('1.3.6.1.2.1.2.2.1.17.1', Counter(2)),
                VarBind('1.3.6.1.2.1.2.2.1.17.10', Counter(442)),
                VarBind('1.3.6.1.2.1.2.2.1.18.1', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.18.10', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.19.1', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.19.10', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.20.1', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.20.10', Counter(0)),
                VarBind('1.3.6.1.2.1.2.2.1.21.1',  Gauge(0)),
                VarBind('1.3.6.1.2.1.2.2.1.21.10',  Gauge(0)),
                VarBind('1.3.6.1.2.1.2.2.1.22.1', ObjectIdentifier(0, 0)),
                VarBind('1.3.6.1.2.1.2.2.1.22.10', ObjectIdentifier(0, 0))
            ]
        assert result == expected
