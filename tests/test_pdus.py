# pylint: skip-file

from x690 import decode
from x690.types import Integer, ObjectIdentifier, OctetString, Sequence

from puresnmp.exc import SnmpError
from puresnmp.pdu import (
    PDU,
    BulkGetRequest,
    GetNextRequest,
    GetRequest,
    GetResponse,
    Null,
    PDUContent,
    SetRequest,
    VarBind,
)

from . import ByteTester, readbytes


def comparable(bytes):
    """
    Helper function to make byte-array output more readable in failed test
    assertions.
    """
    readables = ["%02x" % v for v in bytes]
    return " ".join(readables)


class TestGet(ByteTester):
    def setUp(self):
        super().setUp()
        self.maxDiff = None

    def test_get_request(self):
        expected = (
            b"\x30"  # ASN.1 Header
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
            PDUContent(
                1913359423,
                [VarBind(ObjectIdentifier("1.3.6.1.2.1.1.2.0"), Null())],
            )
        )
        packet = Sequence([Integer(1), OctetString("public"), request])
        result = bytes(packet)

        self.assertBytesEqual(result, expected)

    def test_get_response(self):
        data = (
            b"\x30\x33\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63"
            b"\xa2\x26"
            b"\x02\x04\x72\x0b\x8c\x3f"
            b"\x02\x01\x00\x02\x01\x00"
            b"\x30\x18"
            b"\x30\x16"
            b"\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00"
            b"\x06\x0a\x2b\x06\x01\x04\x01\xbf\x08\x03\x02\x0a"
        )
        result, _ = decode(data)
        expected = Sequence(
            [
                Integer(1),
                OctetString("public"),
                GetResponse(
                    PDUContent(
                        1913359423,  # request-id
                        [
                            VarBind(
                                ObjectIdentifier("1.3.6.1.2.1.1.2.0"),
                                ObjectIdentifier("1.3.6.1.4.1.8072.3.2.10"),
                            )
                        ],
                    ),
                ),
            ]
        )
        self.assertEqual(result, expected)

    def test_get_response_error(self):
        data = (
            b"\x30\x33\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63"
            b"\xa2\x26"
            b"\x02\x04\x72\x0b\x8c\x3f"
            b"\x02\x01\x01\x02\x01\x01"
            b"\x30\x18"
            b"\x30\x16"
            b"\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00"
            b"\x06\x0a\x2b\x06\x01\x04\x01\xbf\x08\x03\x02\x0a"
        )
        with self.assertRaisesRegex(SnmpError, "too big"):
            result, _ = decode(data)
            # We need to "consume" result.value to trigger the error because
            # it's lazy
            _ = result.value[2].value

    def test_get_repr(self):
        oid = ObjectIdentifier("1.3.6.1.2.1.1.2.0")
        request = GetRequest(
            PDUContent(
                1913359423,
                [VarBind(oid, Null())],
            )
        )
        result = repr(request)
        self.assertTrue(
            result.startswith("GetRequest"),
            "repr must start with the class name",
        )
        self.assertIn("1913359423", result, "repr must contain the request ID")
        self.assertIn(repr(oid), result, "repr must contain the request OID")

    def test_multiget_request(self):
        expected = readbytes("multiget.hex")
        request = GetRequest(
            PDUContent(
                1913359423,
                [
                    VarBind(
                        ObjectIdentifier("1.3.6.1.2.1.1.2.0"),
                        Null(),
                    ),
                    VarBind(
                        ObjectIdentifier("1.3.6.1.2.1.1.1.0"),
                        Null(),
                    ),
                ],
            )
        )
        packet = Sequence([Integer(1), OctetString("public"), request])
        result = bytes(packet)
        self.assertBytesEqual(result, expected)

    def test_multiget_response(self):
        data = readbytes("multiget_response.hex")
        result, _ = decode(data)
        expected = Sequence(
            [
                Integer(1),
                OctetString("public"),
                GetResponse(
                    PDUContent(
                        1913359423,  # request-id
                        [
                            VarBind(
                                ObjectIdentifier("1.3.6.1.2.1.1.2.0"),
                                ObjectIdentifier("1.3.6.1.4.1.8072.3.2.10"),
                            ),
                            VarBind(
                                ObjectIdentifier("1.3.6.1.2.1.1.1.0"),
                                OctetString(
                                    "Linux 7fbf2f0c363d 4.4.0-28-generic "
                                    "#47-Ubuntu SMP Fri Jun 24 10:09:13 UTC "
                                    "2016 x86_64"
                                ),
                            ),
                        ],
                    ),
                ),
            ]
        )
        self.assertEqual(result, expected)


class TestWalk(ByteTester):
    """
    Tests related to normal SNMP walks. Responses for walks are the same as for
    GETs, so we only need to cover the requests.
    """

    def test_request(self):
        expected = readbytes("walk_dot.hex")

        request = GetNextRequest(
            PDUContent(499509692, [VarBind(ObjectIdentifier("1"), Null())])
        )
        packet = Sequence([Integer(1), OctetString("public"), request])
        result = bytes(packet)
        self.assertBytesEqual(result, expected)


class TestSet(ByteTester):
    def test_request(self):
        expected = readbytes("set_request.hex")

        request = SetRequest(
            PDUContent(
                499509692,
                [
                    VarBind(
                        ObjectIdentifier("1.3.6.1.2.1.2.2.0"),
                        OctetString(b"hello@world.com"),
                    )
                ],
            )
        )
        packet = Sequence([Integer(1), OctetString("private"), request])
        result = bytes(packet)
        self.assertBytesEqual(result, expected)


class TestBulkGet(ByteTester):
    """
    BulkGet also receives a default "get" response, so there's no need to test
    this in this TestCase.
    """

    def test_request(self):
        expected = readbytes("bulk_get_request.hex")

        request = BulkGetRequest(
            437387882,
            0,  # non-repeaters
            5,  # max-repeaters
            ObjectIdentifier("1.3.6.1.2.1.2.2.0"),
            ObjectIdentifier("1.3.6.1.2.1.2.3.0"),
        )
        packet = Sequence([Integer(1), OctetString("public"), request])

        result = bytes(packet)
        self.assertBytesEqual(result, expected)

    def test_repr(self):
        request = BulkGetRequest(1234, 1, 2, ObjectIdentifier("1.2.3"))
        result = repr(request)
        expected = "BulkGetRequest(1234, 1, 2, ObjectIdentifier('1.2.3'))"
        self.assertEqual(result, expected)


class TestError(ByteTester):
    """
    We want to make sure error packets contain enough information in the
    exception instances.
    """

    def test_gen_error(self):
        pdu = PDU(
            PDUContent(
                123,
                [VarBind(ObjectIdentifier("1.2.3"), Integer(1))],
                error_status=5,
                error_index=1,
            )
        )

        with self.assertRaisesRegex(SnmpError, "genErr.*1.2.3") as exc:
            PDU.decode(bytes(pdu))

        self.assertEqual(exc.exception.error_status, 5)
        self.assertEqual(exc.exception.offending_oid, ObjectIdentifier("1.2.3"))

    def test_non_standard_error(self):
        pdu = PDU(
            PDUContent(
                123,
                [VarBind(ObjectIdentifier("1.2.3"), Integer(1))],
                error_status=7,
                error_index=1,
            )
        )
        with self.assertRaisesRegex(SnmpError, "unknown.*error.*1.2.3") as exc:
            PDU.decode(bytes(pdu))
        self.assertEqual(exc.exception.error_status, 7)
        self.assertEqual(exc.exception.offending_oid, ObjectIdentifier("1.2.3"))


class TestVarBind(ByteTester):
    """
    This class tests the necessary functionalities of VarBind instances
    """

    def setUp(self):
        self.varbind = VarBind(ObjectIdentifier("1.2"), "world")

    def test_unpacking(self):
        """
        VarBinds should be unpackagbe/destructuring should work
        """
        a, b = self.varbind
        self.assertEqual((a, b), (ObjectIdentifier("1.2"), "world"))

    def test_indexing(self):
        """
        Accessing values by index should work
        """
        a, b = self.varbind[0], self.varbind[1]
        self.assertEqual((a, b), (ObjectIdentifier("1.2"), "world"))

    def test_attrs(self):
        """
        Accessing values by attribute should work
        """
        a, b = self.varbind.oid, self.varbind.value
        self.assertEqual((a, b), (ObjectIdentifier("1.2"), "world"))
