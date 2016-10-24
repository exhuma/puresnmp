"""
Test the "external" interface.

The "external" interface is what the user sees. It should be pythonic and easy
to use.
"""


from datetime import timedelta
from unittest.mock import patch, call
import unittest

from puresnmp import (
    BulkResult,
    bulkget,
    bulkwalk,
    get,
    getnext,
    multiget,
    multiset,
    multiwalk,
    set,
    table,
    walk,
)
from puresnmp.const import Version
from puresnmp.exc import SnmpError, NoSuchOID
from puresnmp.pdu import GetRequest, VarBind, GetNextRequest, BulkGetRequest
from puresnmp.x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
)

from . import readbytes


class TestGet(unittest.TestCase):

    def test_get_call_args(self):
        """
        Test the call arguments of "get"
        """
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            GetRequest(0, ObjectIdentifier(1, 2, 3))
        )
        with patch('puresnmp.send') as mck, \
                patch('puresnmp.get_request_id') as mck2:
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

    def test_get_multiple_return_binds(self):
        """
        A "GET" response should only return one varbind.
        """
        data = readbytes('get_sysoid_01_error.hex')
        with patch('puresnmp.send') as mck:
            mck.return_value = data
            with self.assertRaisesRegexp(SnmpError, 'varbind'):
                get('::1', 'private', '1.2.3')

    def test_get_non_existing_oid(self):
        """
        A "GET" response on a non-existing OID should raise an appropriate
        exception.
        """
        data = readbytes('get_non_existing.hex')
        with patch('puresnmp.send') as mck:
            mck.return_value = data
            with self.assertRaises(NoSuchOID):
                get('::1', 'private', '1.2.3')


class TestWalk(unittest.TestCase):

    def test_walk(self):
        response_1 = readbytes('walk_response_1.hex')
        response_2 = readbytes('walk_response_2.hex')
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
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.5.1'), 10000000
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.5.13'), 4294967295
        )]

        with patch('puresnmp.send') as mck:
            mck.side_effect = mocked_responses
            result = list(walk('::1', 'public', '1.3.6.1.2.1.2.2.1.5'))
        self.assertEqual(result, expected)

    def test_walk_multiple_return_binds(self):
        """
        A "WALK" response should only return one varbind.
        """
        data = readbytes('get_sysoid_01_error.hex')
        with patch('puresnmp.send') as mck:
            mck.return_value = data
            with self.assertRaisesRegexp(SnmpError, 'varbind'):
                next(walk('::1', 'private', '1.2.3'))


class TestSet(unittest.TestCase):

    def test_set_without_type(self):
        """
        As we need typing information, we have to hand in an instance of
        supported types (a subclass of puresnmp.x690.Type).
        """
        with patch('puresnmp.send'):
            with self.assertRaisesRegexp(TypeError, 'Type'):
                set('::1', 'private', '1.2.3', 12)

    def test_set(self):
        data = readbytes('set_response.hex')
        with patch('puresnmp.send') as mck:
            mck.return_value = data
            set('::1', 'private', '1.3.6.1.2.1.1.4.0',
                OctetString(b'hello@world.com'))

    def test_set_multiple_varbind(self):
        """
        SET responses should only contain one varbind.
        """
        data = readbytes('set_response_multiple.hex')
        with patch('puresnmp.send') as mck:
            mck.return_value = data
            with self.assertRaisesRegexp(SnmpError, 'varbind'):
                set('::1', 'private', '1.3.6.1.2.1.1.4.0',
                    OctetString(b'hello@world.com'))


class TestMultiGet(unittest.TestCase):

    def test_multiget(self):
        data = readbytes('multiget_response.hex')
        expected = ['1.3.6.1.4.1.8072.3.2.10',
                    b"Linux 7fbf2f0c363d 4.4.0-28-generic #47-Ubuntu SMP Fri "
                    b"Jun 24 10:09:13 UTC 2016 x86_64"]
        with patch('puresnmp.send') as mck:
            mck.return_value = data
            result = multiget('::1', 'private', [
                '1.3.6.1.2.1.1.2.0',
                '1.3.6.1.2.1.1.1.0',
            ])
        self.assertEqual(result, expected)


class TestMultiWalk(unittest.TestCase):

    def test_multi_walk(self):
        response_1 = readbytes('multiwalk_response_1.hex')
        response_2 = readbytes('multiwalk_response_2.hex')
        response_3 = readbytes('multiwalk_response_3.hex')

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
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.1.1'), 1
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.2.1'), b'lo'
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.1.78'), 78
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.2.78'), b'eth0'
        )]

        with patch('puresnmp.send') as mck:
            mck.side_effect = mocked_responses
            result = list(multiwalk('::1', 'public', [
                '1.3.6.1.2.1.2.2.1.1',
                '1.3.6.1.2.1.2.2.1.2'
            ]))
        # TODO (advanced): should order matter in the following result?
        self.assertCountEqual(result, expected)


class TestMultiSet(unittest.TestCase):

    def test_multiset(self):
        """
        Test setting multiple OIDs at once.

        NOTE: The OID '1.3.6.1.2.1.1.5.0' below is manually edited for
              unit-testing. It probably has a different type in the real world!
        """
        data = readbytes('multiset_response.hex')
        with patch('puresnmp.send') as mck:
            mck.return_value = data
            result = multiset('::1', 'private', [
                ('1.3.6.1.2.1.1.4.0', OctetString(b'hello@world.com')),
                ('1.3.6.1.2.1.1.5.0', OctetString(b'hello@world.com')),
            ])
        expected = {
            '1.3.6.1.2.1.1.4.0': b'hello@world.com',
            '1.3.6.1.2.1.1.5.0': b'hello@world.com',
        }
        self.assertEqual(result, expected)


class TestGetNext(unittest.TestCase):

    def test_get_call_args(self):
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            GetNextRequest(0, ObjectIdentifier(1, 2, 3))
        )
        with patch('puresnmp.send') as mck, \
                patch('puresnmp.get_request_id') as mck2:
            mck2.return_value = 0
            mck.return_value = data
            getnext('::1', 'public', '1.2.3')
            mck.assert_called_with('::1', 161, bytes(packet))

    def test_getnext(self):
        data = readbytes('getnext_response.hex')
        expected = VarBind('1.3.6.1.6.3.1.1.6.1.0', 354522558)

        with patch('puresnmp.send') as mck:
            mck.return_value = data
            result = getnext('::1', 'private', '1.3.6.1.5')
        self.assertEqual(result, expected)


class TestGetBulkGet(unittest.TestCase):

    def test_get_call_args(self):
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            BulkGetRequest(0, 1, 2,
                           ObjectIdentifier(1, 2, 3),
                           ObjectIdentifier(1, 2, 4))
        )
        with patch('puresnmp.send') as mck, \
                patch('puresnmp.get_request_id') as mck2:
            mck2.return_value = 0
            mck.return_value = data
            bulkget('::1', 'public',
                    ['1.2.3'],
                    ['1.2.4'],
                    max_list_size=2)
            mck.assert_called_with('::1', 161, bytes(packet))


    def test_bulkget(self):
        data = readbytes('bulk_get_response.hex')
        expected = BulkResult(
            {'1.3.6.1.2.1.1.1.0': b'Linux 7e68e60fe303 4.4.0-28-generic '
             b'#47-Ubuntu SMP Fri Jun 24 10:09:13 UTC 2016 x86_64'},
            {'1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1': 10,
             '1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1': b'\x02B\xe2\xc5\x8d\t',
             '1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1': b'\xac\x11\x00\x01',
             '1.3.6.1.2.1.4.1.0': 1,
             '1.3.6.1.2.1.4.3.0': 57})

        with patch('puresnmp.send') as mck:
            mck.return_value = data
            result = bulkget('::1', 'public',
                             ['1.3.6.1.2.1.1.1'],
                             ['1.3.6.1.2.1.3.1'],
                             max_list_size=5)
        self.assertEqual(result, expected)


class TestGetBulkWalk(unittest.TestCase):

    def test_get_call_args(self):
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            BulkGetRequest(0, 0, 2, ObjectIdentifier(1, 2, 3))
        )
        with patch('puresnmp.send') as mck, \
                patch('puresnmp.get_request_id') as mck2:
            mck2.return_value = 0
            mck.return_value = data

            # we need to wrap this in a list to consume the generator.
            list(bulkwalk('::1', 'public',
                          ['1.2.3'],
                          bulk_size=2))
            mck.assert_called_with('::1', 161, bytes(packet))


    @patch('puresnmp.send')
    @patch('puresnmp.get_request_id')
    def test_bulkwalk(self, mck_rid, mck_send):
        req1 = readbytes('bulkwalk_request_1.hex')
        req2 = readbytes('bulkwalk_request_2.hex')
        req3 = readbytes('bulkwalk_request_3.hex')

        responses = [
            readbytes('bulkwalk_response_1.hex'),
            readbytes('bulkwalk_response_2.hex'),
            readbytes('bulkwalk_response_3.hex'),
        ]
        mck_send.side_effect = responses

        request_ids = [1001613222, 1001613223, 1001613224]
        mck_rid.side_effect = request_ids

        result = list(bulkwalk('127.0.0.1', 'private', ['1.3.6.1.2.1.2.2'],
                               bulk_size=20))

        self.assertEqual(mck_send.mock_calls, [
            call('127.0.0.1', 161, req1),
            call('127.0.0.1', 161, req2),
            call('127.0.0.1', 161, req3),
        ])

        # TODO (advanced): Type information is lost for timeticks and OIDs
        expected = [
            VarBind('1.3.6.1.2.1.2.2.1.1.1', 1),
            VarBind('1.3.6.1.2.1.2.2.1.1.10', 10),
            VarBind('1.3.6.1.2.1.2.2.1.2.1', b"lo"),
            VarBind('1.3.6.1.2.1.2.2.1.2.10', b"eth0"),
            VarBind('1.3.6.1.2.1.2.2.1.3.1', 24),
            VarBind('1.3.6.1.2.1.2.2.1.3.10', 6),
            VarBind('1.3.6.1.2.1.2.2.1.4.1', 65536),
            VarBind('1.3.6.1.2.1.2.2.1.4.10', 1500),
            VarBind('1.3.6.1.2.1.2.2.1.5.1',  10000000),
            VarBind('1.3.6.1.2.1.2.2.1.5.10',  4294967295),
            VarBind('1.3.6.1.2.1.2.2.1.6.1', b""),
            VarBind('1.3.6.1.2.1.2.2.1.6.10', b"\x02\x42\xAC\x11\x00\x02"),
            VarBind('1.3.6.1.2.1.2.2.1.7.1', 1),
            VarBind('1.3.6.1.2.1.2.2.1.7.10', 1),
            VarBind('1.3.6.1.2.1.2.2.1.8.1', 1),
            VarBind('1.3.6.1.2.1.2.2.1.8.10', 1),
            VarBind('1.3.6.1.2.1.2.2.1.9.1', timedelta(0)),
            VarBind('1.3.6.1.2.1.2.2.1.9.10', timedelta(0)),
            VarBind('1.3.6.1.2.1.2.2.1.10.1', 172),
            VarBind('1.3.6.1.2.1.2.2.1.10.10', 60558),
            VarBind('1.3.6.1.2.1.2.2.1.11.1', 2),
            VarBind('1.3.6.1.2.1.2.2.1.11.10', 564),
            VarBind('1.3.6.1.2.1.2.2.1.12.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.12.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.13.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.13.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.14.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.14.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.15.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.15.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.16.1', 172),
            VarBind('1.3.6.1.2.1.2.2.1.16.10', 44295),
            VarBind('1.3.6.1.2.1.2.2.1.17.1', 2),
            VarBind('1.3.6.1.2.1.2.2.1.17.10', 442),
            VarBind('1.3.6.1.2.1.2.2.1.18.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.18.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.19.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.19.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.20.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.20.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.21.1',  0),
            VarBind('1.3.6.1.2.1.2.2.1.21.10',  0),
            VarBind('1.3.6.1.2.1.2.2.1.22.1', '0.0'),  # TODO: type info is lost
            VarBind('1.3.6.1.2.1.2.2.1.22.10', '0.0'),  # TODO: type info is lost
        ]

        # TODO: Expected types per OID:
        # 1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
        # 1.3.6.1.2.1.2.2.1.1.10 = INTEGER: 10
        # 1.3.6.1.2.1.2.2.1.2.1 = STRING: "lo"
        # 1.3.6.1.2.1.2.2.1.2.10 = STRING: "eth0"
        # 1.3.6.1.2.1.2.2.1.3.1 = INTEGER: 24
        # 1.3.6.1.2.1.2.2.1.3.10 = INTEGER: 6
        # 1.3.6.1.2.1.2.2.1.4.1 = INTEGER: 65536
        # 1.3.6.1.2.1.2.2.1.4.10 = INTEGER: 1500
        # 1.3.6.1.2.1.2.2.1.5.1 = Gauge32: 10000000
        # 1.3.6.1.2.1.2.2.1.5.10 = Gauge32: 4294967295
        # 1.3.6.1.2.1.2.2.1.6.1 = ""
        # 1.3.6.1.2.1.2.2.1.6.10 = Hex-STRING: 02 42 AC 11 00 02
        # 1.3.6.1.2.1.2.2.1.7.1 = INTEGER: 1
        # 1.3.6.1.2.1.2.2.1.7.10 = INTEGER: 1
        # 1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1
        # 1.3.6.1.2.1.2.2.1.8.10 = INTEGER: 1
        # 1.3.6.1.2.1.2.2.1.9.1 = Timeticks: (0) 0:00:00.00
        # 1.3.6.1.2.1.2.2.1.9.10 = Timeticks: (0) 0:00:00.00
        # 1.3.6.1.2.1.2.2.1.10.1 = Counter32: 172
        # 1.3.6.1.2.1.2.2.1.10.10 = Counter32: 60558

        # 1.3.6.1.2.1.2.2.1.11.1 = Counter32: 2
        # 1.3.6.1.2.1.2.2.1.11.10 = Counter32: 564
        # 1.3.6.1.2.1.2.2.1.12.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.12.10 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.13.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.13.10 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.14.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.14.10 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.15.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.15.10 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.16.1 = Counter32: 172
        # 1.3.6.1.2.1.2.2.1.16.10 = Counter32: 44295
        # 1.3.6.1.2.1.2.2.1.17.1 = Counter32: 2
        # 1.3.6.1.2.1.2.2.1.17.10 = Counter32: 442
        # 1.3.6.1.2.1.2.2.1.18.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.18.10 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.19.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.19.10 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.20.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.20.10 = Counter32: 0

        # 1.3.6.1.2.1.2.2.1.21.1 = Gauge32: 0
        # 1.3.6.1.2.1.2.2.1.21.10 = Gauge32: 0
        # 1.3.6.1.2.1.2.2.1.22.1 = OID: ccitt.0
        # 1.3.6.1.2.1.2.2.1.22.10 = OID: ccitt.0
        self.assertEqual(result, expected)


class TestGetTable(unittest.TestCase):

    @patch('puresnmp.walk')
    @patch('puresnmp.tablify')
    @patch('puresnmp.get_request_id')
    def test_table(self, mck_rid, mck_tablify, mck_walk):
        mck_rid.return_value = 0
        tmp = object()  # dummy return value
        mck_walk.return_value = tmp
        table('::1', 'public', '1.2.3.4', port=161, num_base_nodes=2)
        mck_walk.assert_called_with('::1', 'public', '1.2.3.4', port=161)
        mck_tablify.assert_called_with(tmp, num_base_nodes=2)
