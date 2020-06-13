# pylint: skip-file


"""
Test the external "raw" interface.

"raw" means that types are not converted to pythonic types but are returned as
PureSNMP object instances.
"""

from __future__ import print_function

import sys
import unittest
from datetime import timedelta
from logging import WARNING, Handler, getLevelName, getLogger
from unittest import skipUnless

import six

from puresnmp.api.raw import (
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
    walk,
)
from puresnmp.const import Version
from puresnmp.exc import FaultySNMPImplementation, NoSuchOID, SnmpError
from puresnmp.pdu import (
    BulkGetRequest,
    GetNextRequest,
    GetRequest,
    GetResponse,
    VarBind
)
from puresnmp.transport import SocketInfo, SocketResponse
from puresnmp.types import Counter, Gauge, IpAddress, TimeTicks
from puresnmp.util import BulkResult
from puresnmp.x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
    to_bytes
)

from . import ByteTester, CapturingHandler, readbytes, readbytes_multiple

try:
    from unittest.mock import patch, call
except ImportError:
    from mock import patch, call  # type: ignore



class TestGet(ByteTester):

    def test_get_string(self):
        data = readbytes('get_sysdescr_01.hex')
        expected = OctetString(
            b'Linux d24cf7f36138 4.4.0-28-generic #47-Ubuntu SMP '
            b'Fri Jun 24 10:09:13 UTC 2016 x86_64')
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            result = get('::1', 'private', '1.2.3')
        self.assertEqual(result, expected)

    def test_get_oid(self):
        data = readbytes('get_sysoid_01.hex')
        expected = ObjectIdentifier.from_string('1.3.6.1.4.1.8072.3.2.10')
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            result = get('::1', 'private', '1.2.3')
        self.assertEqual(result, expected)

    def test_get_multiple_return_binds(self):
        """
        A "GET" response should only return one varbind.
        """
        data = readbytes('get_sysoid_01_error.hex')
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            with six.assertRaisesRegex(self, SnmpError, 'varbind'):
                get('::1', 'private', '1.2.3')

    def test_get_non_existing_oid(self):
        """
        A "GET" response on a non-existing OID should raise an appropriate
        exception.
        """
        data = readbytes('get_non_existing.hex')
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            with self.assertRaises(NoSuchOID):
                get('::1', 'private', '1.2.3')


class TestWalk(unittest.TestCase):

    def test_walk(self):
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

        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.side_effect = [response_1, response_2, response_3]
            mck().get_request_id.return_value = 0
            result = list(walk('::1', 'public', '1.3.6.1.2.1.2.2.1.5'))
        self.assertEqual(result, expected)

    def test_walk_multiple_return_binds(self):
        """
        A "WALK" response should only return one varbind.
        """
        data = readbytes('get_sysoid_01_error.hex')
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            with six.assertRaisesRegex(self, SnmpError, 'varbind'):
                next(walk('::1', 'private', '1.2.3'))


class TestMultiGet(unittest.TestCase):

    def test_multiget(self):
        data = readbytes('multiget_response.hex')
        expected = [
            ObjectIdentifier.from_string('1.3.6.1.4.1.8072.3.2.10'),
            OctetString(b"Linux 7fbf2f0c363d 4.4.0-28-generic "
                        b"#47-Ubuntu SMP Fri Jun 24 10:09:13 "
                        b"UTC 2016 x86_64")
        ]
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            result = multiget('::1', 'private', [
                '1.3.6.1.2.1.1.2.0',
                '1.3.6.1.2.1.1.1.0',
            ])
            result = list(result)
        self.assertEqual(result, expected)


class TestMultiWalk(unittest.TestCase):

    def test_multi_walk(self):
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

        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.side_effect = [response_1, response_2, response_3]
            mck().get_request_id.return_value = 0
            result = list(multiwalk('::1', 'public', [
                '1.3.6.1.2.1.2.2.1.1',
                '1.3.6.1.2.1.2.2.1.2'
            ]))
        self.assertEqual(result, expected)

    def test_multiwalk_non_containment(self):
        '''
        Running a multiwalk should raise an exception if the agent returns OIDs
        which are not properly increasing.
        '''
        from puresnmp.pdu import GetResponse
        OID = ObjectIdentifier.from_string

        # First case: Returned OIDs are the same
        response = Sequence(
            Integer(1),
            OctetString(b'public'),
            GetResponse(
                123,
                [
                    VarBind(oid=OID('1.2.3'), value=Integer(30)),
                    VarBind(oid=OID('2.3.4'), value=Integer(40)),
                ]
            )
        )
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.side_effect = [to_bytes(response)]
            mck().get_request_id.return_value = 0
            with self.assertRaises(FaultySNMPImplementation):
                list(multiwalk('::1', 'public', [
                    '1.2.3',
                    '2.3.4',
                ]))


        # Second case: Returned OIDs are smaller
        response = Sequence(
            Integer(1),
            OctetString(b'public'),
            GetResponse(
                123,
                [
                    VarBind(oid=OID('1.2.2'), value=Integer(30)),
                    VarBind(oid=OID('2.3.3'), value=Integer(40)),
                ]
            )
        )
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.side_effect = [to_bytes(response)]
            mck().get_request_id.return_value = 0
            with self.assertRaises(FaultySNMPImplementation):
                list(multiwalk('::1', 'public', [
                    '1.2.3',
                    '2.3.4',
                ]))

    def test_eom(self):
        '''
        A test for a walk operation which runs into the endOfMibView marker
        '''

        data_generator = readbytes_multiple('x690/multiwalk_endofmibview.hex')

        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.side_effect = data_generator
            mck().get_request_id.return_value = 0
            result = multiwalk(u'::1', u'public', [
                u'1.3.6.1.6.3.16.1.5.2.1.6.6.95.110.111.110.101.95.1',
            ])
            result = list(result)

        OID = ObjectIdentifier.from_string
        root = '1.3.6.1.6.3.16.1.5.2.1.6.6.95.110.111.110.101.95.1.'
        expected = [
            VarBind(OID(root+'0'), Integer(1)),
            VarBind(OID(root+'1'), Integer(1)),
            VarBind(OID(root+'2'), Integer(1)),
        ]

        self.assertEqual(result, expected)


class TestMultiSet(unittest.TestCase):

    def test_multiset(self):
        """
        Test setting multiple OIDs at once.

        NOTE: The OID '1.3.6.1.2.1.1.5.0' below is manually edited for
              unit-testing. It probably has a different type in the real world!
        """
        data = readbytes('multiset_response.hex')
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            result = multiset('::1', 'private', [
                ('1.3.6.1.2.1.1.4.0', OctetString(b'hello@world.com')),
                ('1.3.6.1.2.1.1.5.0', OctetString(b'hello@world.com')),
            ])
        expected = {
            '1.3.6.1.2.1.1.4.0': OctetString(b'hello@world.com'),
            '1.3.6.1.2.1.1.5.0': OctetString(b'hello@world.com'),
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
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            getnext('::1', 'public', '1.2.3')
            mck.assert_called_with(timeout=6)
            mck().send.assert_called_with('::1', 161, to_bytes(packet))

    def test_getnext(self):
        data = readbytes('getnext_response.hex')
        expected = VarBind('1.3.6.1.6.3.1.1.6.1.0', Integer(354522558))

        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            result = getnext('::1', 'private', '1.3.6.1.5')
        self.assertEqual(result, expected)

    def test_getnext_increasing_oid_strict(self):
        '''
        When running "getnext" we expect a different OID than the one we passed
        in. If not, this can cause endless-loops in the worst case. Faulty SNMP
        implementations may behave this way!
        '''
        requested_oid = ObjectIdentifier(1, 2, 3, 4)
        response_object = Sequence(
            Integer(1),
            OctetString(b'public'),
            GetResponse(
                234,
                [VarBind(requested_oid, Integer(123))]
            )
        )
        response_bytes = to_bytes(response_object)

        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = response_bytes
            mck().get_request_id.return_value = 0
            with self.assertRaises(FaultySNMPImplementation):
                getnext('::1', 'private', '1.2.3.4')

    def test_walk_increasing_oid_lenient(self):
        '''
        We want to be able to allow faulty SNMP implementations to at least try
        to fetch the values in a walk which are not increasing. It should read
        up to the values which are no longer increasing and emit a warning.
        '''
        logger = getLogger('puresnmp')
        handler = CapturingHandler()
        logger.addHandler(handler)

        response_binds = [
            VarBind(ObjectIdentifier(1, 2, 3), Integer(123)),
            VarBind(ObjectIdentifier(1, 2, 4), Integer(124)),
            VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),
            VarBind(ObjectIdentifier(1, 2, 1), Integer(121)),  # non-increasing
        ]
        response_packets = [
            Sequence(
                Integer(1),
                OctetString(b'public'),
                GetResponse(
                    234,
                    [bind]
                )
            )
            for bind in response_binds
        ]
        response_bytes = [to_bytes(packet) for packet in response_packets]

        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.side_effect = response_bytes
            mck().get_request_id.return_value = 0
            result = list(walk('::1', 'private', '1.2', errors='warn'))


        # The last OID in the mocked responses is decreasing so we want to read
        # just up to that point.
        expected = [
            VarBind(ObjectIdentifier(1, 2, 3), Integer(123)),
            VarBind(ObjectIdentifier(1, 2, 4), Integer(124)),
            VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),
        ]
        self.assertEqual(result, expected)

        # We also want to make sure that we have a proper warning about this
        handler.assertContains(WARNING, r'.*1.2.1.*1.2.5.*')
        logger.removeHandler(handler)


    def test_walk_endless_loop(self):
        '''
        In rare cases, some devices fall into an endless loop by returning the
        requested OID on a "getnext" call during a "walk" operation. A SNMP
        client behaving according to the SNMP spec will fall into an endless
        loop. This test fakes such a case and revents the loop.
        '''
        response_binds = [
            VarBind(ObjectIdentifier(1, 2, 3), Integer(123)),
            VarBind(ObjectIdentifier(1, 2, 4), Integer(124)),
            VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),
            VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),  # same OID
            VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),  # same OID
            VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),  # same OID
        ]
        response_packets = [
            Sequence(
                Integer(1),
                OctetString(b'public'),
                GetResponse(
                    234,
                    [bind]
                )
            )
            for bind in response_binds
        ]
        response_bytes = [to_bytes(packet) for packet in response_packets]

        handler = CapturingHandler()
        logger = getLogger('puresnmp')
        logger.addHandler(handler)
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.side_effect = response_bytes
            mck().get_request_id.return_value = 0
            result = list(walk('::1', 'private', '1.2', errors='warn'))
        logger.removeHandler(handler)


        # The last OID in the mocked responses is decreasing so we want to read
        # just up to that point.
        expected = [
            VarBind(ObjectIdentifier(1, 2, 3), Integer(123)),
            VarBind(ObjectIdentifier(1, 2, 4), Integer(124)),
            VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),
        ]
        self.assertEqual(result, expected)

        # We also want to make sure that we have a proper warning about this
        handler.assertContains(WARNING, r'.*1.2.5.*')


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
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            bulkget('::1', 'public',
                    ['1.2.3'],
                    ['1.2.4'],
                    max_list_size=2)
            mck.assert_called_with(timeout=6)
            mck().send.assert_called_with('::1', 161, to_bytes(packet))

    def test_bulkget(self):
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

        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            result = bulkget('::1', 'public',
                             ['1.3.6.1.2.1.1.1'],
                             ['1.3.6.1.2.1.3.1'],
                             max_list_size=5)
        self.assertEqual(result, expected)

    def test_eom(self):
        '''
        Test a bulg-get operation which runs into the "endOfMibView" marker.
        '''

        data = readbytes('x690/bulk_get_eom_response.hex')
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0
            result = bulkget('::1', 'public', [], ['1.2.4'], max_list_size=10)

        expected_scalars = {}
        self.assertEqual(result.scalars, expected_scalars)

        root = '1.3.6.1.6.3.16.1.5.2.1.6.6.95.110.111.110.101.95.1.'
        expected_listing = {
            root + '0': Integer(1),
            root + '1': Integer(1),
            root + '2': Integer(1),
        }

        self.assertEqual(result.listing, expected_listing)


class TestGetBulkWalk(unittest.TestCase):

    def test_get_call_args(self):
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            BulkGetRequest(0, 0, 2, ObjectIdentifier(1, 2, 3))
        )
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0

            # we need to wrap this in a list to consume the generator.
            list(bulkwalk('::1', 'public',
                          ['1.2.3'],
                          bulk_size=2))
            mck.assert_called_with(timeout=6)
            mck().send.assert_called_with('::1', 161, to_bytes(packet))

    def test_get_call_args_issue_22(self):
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            BulkGetRequest(0, 0, 2, ObjectIdentifier(1, 2, 3))
        )
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().send.return_value = data
            mck().get_request_id.return_value = 0

            with six.assertRaisesRegex(self, TypeError, 'OIDS.*list'):
                # we need to wrap this in a list to consume the generator.
                list(bulkwalk('::1', 'public', '1.2.3', bulk_size=2))

    @patch('puresnmp.api.raw.Transport')
    def test_bulkwalk(self, mck_transport):
        req1 = readbytes('bulkwalk_request_1.hex')
        req2 = readbytes('bulkwalk_request_2.hex')
        req3 = readbytes('bulkwalk_request_3.hex')

        responses = [
            readbytes('bulkwalk_response_1.hex'),
            readbytes('bulkwalk_response_2.hex'),
            readbytes('bulkwalk_response_3.hex'),
        ]
        mck_transport().send.side_effect = responses

        request_ids = [1001613222, 1001613223, 1001613224]
        mck_transport().get_request_id.side_effect = request_ids

        result = list(bulkwalk('127.0.0.1', 'private', ['1.3.6.1.2.1.2.2'],
                               bulk_size=20))

        mck_transport.assert_called_with(timeout=6)
        self.assertEqual(mck_transport().send.mock_calls, [
            call('127.0.0.1', 161, req1),
            call('127.0.0.1', 161, req2),
            call('127.0.0.1', 161, req3),
        ])

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
        self.assertEqual(result, expected)


class TestTable(unittest.TestCase):

    @patch('puresnmp.api.raw.walk')
    def test_table(self, mck_walk):
        mck_walk.return_value = [
            VarBind('1.2.1.1.1', OctetString(b'row 1 col 1')),
            VarBind('1.2.1.1.2', OctetString(b'row 2 col 1')),
            VarBind('1.2.1.2.1', OctetString(b'row 1 col 2')),
            VarBind('1.2.1.2.2', OctetString(b'row 2 col 2')),
        ]
        result = table('192.0.2.1', 'private', '1.2')
        expected = [
            {'0': '1',
             '1': OctetString('row 1 col 1'),
             '2': OctetString('row 1 col 2')},
            {'0': '2',
             '1': OctetString('row 2 col 1'),
             '2': OctetString('row 2 col 2')},
        ]
        self.assertEqual(sorted(result, key=lambda x: x['0']), expected)

    @patch('puresnmp.api.raw.walk')
    def test_table_complex_row_id(self, mck_walk):
        mck_walk.return_value = [
            VarBind('1.2.1.1.1.1', OctetString(b'row 1.1.1 col 1')),
            VarBind('1.2.1.2.1.1', OctetString(b'row 2.1.1 col 1')),
            VarBind('1.2.2.1.1.1', OctetString(b'row 1.1.1 col 2')),
            VarBind('1.2.2.2.1.1', OctetString(b'row 2.1.1 col 2')),
        ]
        result = table('192.0.2.1', 'private', '1.2', num_base_nodes=2)
        expected = [
            {'0': '1.1.1',
             '1': OctetString('row 1.1.1 col 1'),
             '2': OctetString('row 1.1.1 col 2')},
            {'0': '2.1.1',
             '1': OctetString('row 2.1.1 col 1'),
             '2': OctetString('row 2.1.1 col 2')},
        ]
        self.assertEqual(sorted(result, key=lambda x: x['0']), expected)

    @patch('puresnmp.api.raw.walk')
    def test_table_base_oid(self, mck_walk):
        """
        The "table" function should be capable of detecting the
        "num_base_nodes" value by itself
        """
        mck_walk.return_value = [
            VarBind('1.2.1.1.1.1.1', OctetString(b'row 1.1.1 col 1')),
            VarBind('1.2.1.1.2.1.1', OctetString(b'row 2.1.1 col 1')),
            VarBind('1.2.1.2.1.1.1', OctetString(b'row 1.1.1 col 2')),
            VarBind('1.2.1.2.2.1.1', OctetString(b'row 2.1.1 col 2')),
        ]
        result = table('192.0.2.1', 'private', '1.2')
        expected = [
            {'0': '1.1.1',
             '1': OctetString('row 1.1.1 col 1'),
             '2': OctetString('row 1.1.1 col 2')},
            {'0': '2.1.1',
             '1': OctetString('row 2.1.1 col 1'),
             '2': OctetString('row 2.1.1 col 2')},
        ]
        self.assertEqual(sorted(result, key=lambda x: x['0']), expected)


class TestBulkTable(unittest.TestCase):

    @patch('puresnmp.api.raw.Transport')
    def test_bulktable(self, mck_transport):
        responses = readbytes_multiple('bulktable_response.hex')
        mck_transport().send.side_effect = responses

        request_ids = [1, 2, 3, 4, 5]
        mck_transport().get_request_id.side_effect = request_ids

        result = list(bulktable('127.0.0.1', 'private', '1.3.6.1.2.1.2.2'))

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
        self.assertEqual(sorted(result, key=lambda x: x['0']), expected)


class TestTraps(unittest.TestCase):

    def test_traps(self):
        data_generator = readbytes_multiple("trap_requests.hex")

        def socket_response_generator():
            for blob in data_generator:
                yield SocketResponse(blob, SocketInfo("192.0.2.1", 64001))

        expected = [
            VarBind(ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 3, 0)),
                    TimeTicks(794602)),
            VarBind(ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)),
                    ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1))),
            VarBind(ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1)),
                    Integer(123456)),
            VarBind(ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 3, 0)),
                    TimeTicks(795345)),
            VarBind(ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)),
                    ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1))),
            VarBind(ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1)),
                    Integer(123457)),
            VarBind(ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 3, 0)),
                    TimeTicks(795538)),
            VarBind(ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)),
                    ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1))),
            VarBind(ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1)),
                    Integer(123459)),
        ]
        result = []
        with patch('puresnmp.api.raw.Transport') as mck:
            mck().listen.return_value = socket_response_generator()
            for trap in traps():
                result.extend(trap.varbinds)
        self.assertEqual(result, expected)

    def test_traps_origin(self):
        """
        We want to see where a trap was sent from
        """
        data_generator = readbytes_multiple("trap_requests.hex")
        def socket_response_generator():
            for blob in data_generator:
                yield SocketResponse(blob, SocketInfo("192.0.2.1", 64001))
        # As we import "set" above we are no longer able to create empty sets -_-
        result = {1}
        with patch("puresnmp.api.raw.Transport") as mck:
            mck().listen.return_value = socket_response_generator()
            for trap in traps():
                result.add(trap.source)
        expected = {1, SocketInfo("192.0.2.1", 64001)}
        self.assertEqual(result, expected)
