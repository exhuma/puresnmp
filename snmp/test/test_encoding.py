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


class TestEncoding(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.maxDiff = None

    def test_get_request(self):
        expected = (b"\x30"  # ASN.1 Header
                    b"\x27"  # PDU length
                    b"\x02\x01\x01"  # SNMP Version
                    b"\x04\x06\x70\x75\x62\x6c\x69\x63"  # community ("public")
                    b"\xa0\x1c"  # PDU Type
                    b"\x02\x04\x72\x0b\x8c\x3f"  # Request ID
                    b"\x02\x01\x00"  # Error Type
                    b"\x02\x01\x00"  # Error Index
                    b"\x30"  # Variable Type (List)
                    b"\x0c"  # Length
                    b"\x30"  # Variable Type (List)
                    b"\x0a"  # Length
                    b"\x06"  # Variable Type (OID)
                    b"\x08"  # Length
                    b"\x2b\x06\x01\x02\x01\x01\x02\x00"  # Value
                    )
        packet = GetRequest(
            version=Version.V2C,
            community='public',
            oid=Oid(1, 3, 6, 1, 2, 1, 1, 2, 0)
        )
        result = bytes(packet)
        self.assertEqual(result, expected)

    def test_get_response(self):
        data = (b"\x30\x33\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63"
                b"\xa2\x26"
                b"\x02\x04\x72\x0b\x8c\x3f"
                b"\x02\x01\x00\x02\x01\x00"
                b"\x30\x18"
                b"\x30\x16"
                b"\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00"
                b"\x06\x0a\x2b\x06\x01\x04\x01\xbf\x08\x03\x02\x0a")
        result = unmarshal(data)
        expected = {
            'version': Version.V2C,  # integer (0x02) of length 1 (0x01)
            'community': 'public',  # string (0x04) of length 6 (0x06)
            'pdu_type': Pdu.GET_RESPONSE,
            'request_id': int('720b8c3f', 16),
            'error_code': 0,
            'error_index': 0,
            'value_type': Oid.HEADER,
            'value': '1.3.6.1.4.1.8072.3.2.10',
        }
        self.assertEqual(result, expected)

    def test_invalid(self):
        """
        ASN.1 payload starts with 0x30 (the ASN.1 header)
        """
        data = (b"\x22\x33\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa2\x26"
                b"\x02\x04\x72\x0b\x8c\x3f\x02\x01\x00\x02\x01\x00\x30\x18\x30"
                b"\x16\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00\x06\x0a\x2b\x06"
                b"\x01\x04\x01\xbf\x08\x03\x02\x0a")
        with self.assertRaises(ValueError):
            unmarshal(data)
