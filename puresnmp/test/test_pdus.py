from ..exc import SnmpError
from ..x690.types import (
    Integer,
    Null,
    ObjectIdentifier,
    OctetString,
    Sequence,
)
from ..pdu import (
    BulkGetRequest,
    GetNextRequest,
    GetRequest,
    GetResponse,
    SetRequest,
    VarBind,
)

from ..const import Version
from . import ByteTester, readbytes


def comparable(bytes):
    """
    Helper function to make byte-array output more readable in failed test
    assertions.
    """
    readables = ['%02x' % v for v in bytes]
    return ' '.join(readables)


class TestGet(ByteTester):

    def setUp(self):
        super().setUp()
        self.maxDiff = None

    def test_get_request(self):
        expected = (b"\x30"  # ASN.1 Header
                    b"\x29"  # PDU length
                    b"\x02\x01\x01"  # SNMP Version
                    b"\x04\x06\x70\x75\x62\x6c\x69\x63"  # community ("public")
                    b"\xa0\x1c"  # PDU Type
                    b"\x02\x04\x72\x0b\x8c\x3f"  # Request ID
                    b"\x02\x01\x00"  # Error Type
                    b"\x02\x01\x00"  # Error Index
                    b"\x30"  # Variable Type (Sequence)
                    b"\x0e"  # Length
                    b"\x30"  # Variable Type (Sequence)
                    b"\x0c"  # Length
                    b"\x06"  # Variable Type (OID)
                    b"\x08"  # Length
                    b"\x2b\x06\x01\x02\x01\x01\x02\x00"  # Value
                    b"\x05\x00"  # NULL
                    )

        request = GetRequest(
            1913359423,
            ObjectIdentifier(1, 3, 6, 1, 2, 1, 1, 2, 0),
        )
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            request
        )
        result = bytes(packet)

        self.assertBytesEqual(result, expected)

    def test_get_response(self):
        data = (b"\x30\x33\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63"
                b"\xa2\x26"
                b"\x02\x04\x72\x0b\x8c\x3f"
                b"\x02\x01\x00\x02\x01\x00"
                b"\x30\x18"
                b"\x30\x16"
                b"\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00"
                b"\x06\x0a\x2b\x06\x01\x04\x01\xbf\x08\x03\x02\x0a")
        result = Sequence.from_bytes(data)
        expected = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            GetResponse(
                Integer(1913359423),  # request-id
                [VarBind(
                    ObjectIdentifier(1, 3, 6, 1, 2, 1, 1, 2, 0),
                    ObjectIdentifier(1, 3, 6, 1, 4, 1, 8072, 3, 2, 10)
                )]
            )
        )
        self.assertEqual(result, expected)

    def test_get_response_error(self):
        data = (b"\x30\x33\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63"
                b"\xa2\x26"
                b"\x02\x04\x72\x0b\x8c\x3f"
                b"\x02\x01\x01\x02\x01\x02"
                b"\x30\x18"
                b"\x30\x16"
                b"\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00"
                b"\x06\x0a\x2b\x06\x01\x04\x01\xbf\x08\x03\x02\x0a")
        with self.assertRaisesRegexp(SnmpError, 'tooBig'):
            Sequence.from_bytes(data)

    def test_get_repr(self):
        oid = ObjectIdentifier(1, 3, 6, 1, 2, 1, 1, 2, 0)
        request = GetRequest(
            1913359423,
            oid,
        )
        result = repr(request)
        self.assertTrue(result.startswith('GetRequest'),
                        'repr must start with the class name')
        self.assertIn('1913359423', result, 'repr must contain the request ID')
        self.assertIn(repr(oid), result, 'repr must contain the request OID')

    def test_multiget_request(self):
        expected = readbytes('multiget.hex')
        request = GetRequest(
            1913359423,
            ObjectIdentifier.from_string('1.3.6.1.2.1.1.2.0'),
            ObjectIdentifier.from_string('1.3.6.1.2.1.1.1.0'),
        )
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            request
        )

        result = bytes(packet)
        self.assertBytesEqual(result, expected)

    def test_multiget_response(self):
        data = readbytes('multiget_response.hex')
        result = Sequence.from_bytes(data)
        expected = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            GetResponse(
                Integer(1913359423),  # request-id
                [
                    VarBind(
                        ObjectIdentifier.from_string('1.3.6.1.2.1.1.2.0'),
                        ObjectIdentifier.from_string('1.3.6.1.4.1.8072.3.2.10'),
                    ),
                    VarBind(
                        ObjectIdentifier.from_string('1.3.6.1.2.1.1.1.0'),
                        OctetString("Linux 7fbf2f0c363d 4.4.0-28-generic "
                                    "#47-Ubuntu SMP Fri Jun 24 10:09:13 UTC "
                                    "2016 x86_64")
                    )
                ]
            )
        )
        self.assertEqual(result, expected)


class TestWalk(ByteTester):
    """
    Tests related to normal SNMP walks. Responses for walks are the same as for
    GETs, so we only need to cover the requests.
    """

    def test_request(self):
        expected = readbytes('walk_dot.hex')

        request = GetNextRequest(
            499509692,
            ObjectIdentifier(1))
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            request
        )
        result = bytes(packet)
        self.assertBytesEqual(result, expected)


class TestSet(ByteTester):

    def test_request(self):
        expected = readbytes('set_request.hex')

        request = SetRequest(
            499509692,
            VarBind(ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.0'),
                    OctetString(b'hello@world.com'))
        )
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('private'),
            request
        )
        result = bytes(packet)
        self.assertBytesEqual(result, expected)


class TestBulkGet(ByteTester):
    """
    BulkGet also receives a default "get" response, so there's no need to test
    this in this TestCase.
    """

    def test_request(self):
        expected = readbytes('bulk_get_request.hex')

        request = BulkGetRequest(
            437387882,
            0,  # non-repeaters
            5,  # max-repeaters
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.0'),
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.3.0')
        )
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            request
        )

        result = bytes(packet)
        self.assertBytesEqual(result, expected)
