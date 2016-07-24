import unittest

from ..marshal import (
    GetRequest,
    Integer,
    List,
    Oid,
    Pdu,
    String,
    Version,
    marshal,
    unmarshal,
)


def comparable(bytes):
    """
    Helper function to make byte-array output more readable in failed test
    assertions.
    """
    readables = ['%02x' % v for v in bytes]
    return ' '.join(readables)


class TestEncoding(unittest.TestCase):

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
                    b"\x30"  # Variable Type (List)
                    b"\x0e"  # Length
                    b"\x30"  # Variable Type (List)
                    b"\x0c"  # Length
                    b"\x06"  # Variable Type (OID)
                    b"\x08"  # Length
                    b"\x2b\x06\x01\x02\x01\x01\x02\x00"  # Value
                    b"\x05\x00"  # NULL
                    )

        request = GetRequest(oid=Oid(1, 3, 6, 1, 2, 1, 1, 2, 0))
        request.request_id = 1913359423
        packet = List(
            Integer(Version.V2C),
            String('public'),
            request
        )
        result = bytes(packet)

        self.assertEqual(comparable(result), comparable(expected))

    def test_get_response(self):
        self.skipTest('TODO')
        data = (b"\x30\x33\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63"
                b"\xa2\x26"
                b"\x02\x04\x72\x0b\x8c\x3f"
                b"\x02\x01\x00\x02\x01\x00"
                b"\x30\x18"
                b"\x30\x16"
                b"\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00"
                b"\x06\x0a\x2b\x06\x01\x04\x01\xbf\x08\x03\x02\x0a")
        result = GetResponse.from_bytes(data)
        expected = GetResponse(
            version=Version.V2C,
            community='public',
            oid=Oid(1, 3, 6, 1, 2, 1, 1, 2, 0),
            value=Oid(1, 3, 6, 1, 4, 1, 8072, 3, 2, 10)
        )
        self.assertEqual(result, expected)
