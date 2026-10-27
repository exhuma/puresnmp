# pylint: skip-file

from x690 import decode
from x690.types import Integer, ObjectIdentifier, OctetString, Sequence

from puresnmp.exc import FaultySNMPImplementation, GenErr, SnmpError
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

    def test_error_index_beyond_varbinds(self):
        """
        Ensure an error-index past the end of the varbind list raises the
        error response instead of an IndexError.
        """
        pdu = GetResponse(
            PDUContent(
                123,
                [VarBind(ObjectIdentifier("1.2.3"), Integer(1))],
                error_status=5,
                error_index=3,
            )
        )

        with self.assertRaises(GenErr) as exc:
            PDU.decode(bytes(pdu))

        self.assertEqual(exc.exception.error_status, 5)
        self.assertEqual(exc.exception.offending_oid, ObjectIdentifier())

    def test_error_index_without_varbinds(self):
        """
        Ensure a non-zero error-index with no varbinds raises the error
        response instead of an IndexError.
        """
        pdu = GetResponse(PDUContent(123, [], error_status=5, error_index=1))

        with self.assertRaises(GenErr) as exc:
            PDU.decode(bytes(pdu))

        self.assertEqual(exc.exception.error_status, 5)
        self.assertEqual(exc.exception.offending_oid, ObjectIdentifier())


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


def _tlv(tag, body):
    """
    Encode a single BER tag-length-value triple with a definite length.
    """
    if len(body) < 128:
        length = bytes([len(body)])
    else:
        raw = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + body


def _nested_sequence(depth):
    """
    Build raw BER for a SEQUENCE nested ``depth`` levels deep around an
    empty SEQUENCE. Built as bytes so that very deep nesting does not hit
    Python's recursion limit while constructing the test input.
    """
    encoded = _tlv(0x30, b"")
    for _ in range(depth):
        encoded = _tlv(0x30, encoded)
    return encoded


def _get_response_with_value(value):
    """
    Build raw BER for a GetResponse with one varbind for 1.3.6.1.2.1.1.2.0
    whose value is the given raw BER bytes.
    """
    oid = _tlv(0x06, b"\x2b\x06\x01\x02\x01\x01\x02\x00")
    varbind = _tlv(0x30, oid + value)
    body = (
        _tlv(0x02, b"\x01")  # request-id
        + _tlv(0x02, b"\x00")  # error-status
        + _tlv(0x02, b"\x00")  # error-index
        + _tlv(0x30, varbind)
    )
    return _tlv(0xA2, body)


class TestVarBindValueType(ByteTester):
    """
    Varbind values must be ObjectSyntax values, never constructed SEQUENCEs.
    """

    def test_deeply_nested_sequence_value(self):
        """
        Ensure a varbind value that is a deeply nested SEQUENCE raises
        FaultySNMPImplementation instead of RecursionError.
        """
        data = _get_response_with_value(_nested_sequence(1500))

        with self.assertRaises(FaultySNMPImplementation):
            GetResponse.decode(data).value

    def test_shallow_sequence_value(self):
        """
        Ensure a varbind value that is a two-level SEQUENCE is rejected with
        an error naming the OID and the type, independent of nesting depth.
        """
        data = _get_response_with_value(_nested_sequence(1))

        with self.assertRaises(FaultySNMPImplementation) as exc:
            GetResponse.decode(data).value

        self.assertIn("1.3.6.1.2.1.1.2.0", str(exc.exception))
        self.assertIn("Sequence", str(exc.exception))
