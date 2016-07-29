from ..x690.types import (
    Boolean,
    Integer,
    Oid,
    Sequence,
    String,
    TypeInfo,
)
from ..x690.util import Length, consume_length, encode_length

from . import ByteTester


def make_identifier_test(octet, expected_class, expected_pc, expected_value):
    def fun(self):
        result = TypeInfo.from_bytes(octet)
        expected = TypeInfo(expected_class, expected_pc, expected_value)
        self.assertEqual(result, expected)
    return fun


class TestBoolean(ByteTester):

    def test_encoding_false(self):
        value = Boolean(False)
        result = bytes(value)
        expected = b'\x01\x01\x00'
        self.assertEqual(result, expected)

    def test_encoding_true(self):
        value = Boolean(True)
        result = bytes(value)
        expected = b'\x01\x01\x01'
        self.assertEqual(result, expected)

    def test_decoding_false(self):
        result = Boolean.from_bytes(b'\x01\x01\x00')
        expected = Boolean(False)
        self.assertEqual(result, expected)

    def test_decoding_true(self):
        result = Boolean.from_bytes(b'\x01\x01\x01')
        expected = Boolean(True)
        self.assertEqual(result, expected)

        result = Boolean.from_bytes(b'\x01\x01\x02')
        expected = Boolean(True)
        self.assertEqual(result, expected)

        result = Boolean.from_bytes(b'\x01\x01\xff')
        expected = Boolean(True)
        self.assertEqual(result, expected)

    def test_pythonize(self):
        result = Boolean(True).pythonize()
        expected = True
        self.assertEqual(result, expected)


class TestOid(ByteTester):

    def setUp(self):
        super().setUp()
        self.maxDiff = None

    def test_simple_encoding(self):
        """
        A simple OID with no identifier above 127
        """
        oid = Oid(1, 3, 6, 1, 2, 1)
        result = bytes(oid)
        expected = b'\x06\x05\x2b\x06\x01\x02\x01'
        self.assertEqual(result, expected)

    def test_simple_decoding(self):
        """
        A simple OID with no identifier above 127
        """
        expected = Oid(1, 3, 6, 1, 2, 1)
        result = Oid.from_bytes(b'\x06\x05\x2b\x06\x01\x02\x01')
        self.assertEqual(result, expected)

    def test_multibyte_encoding(self):
        """
        If a sub-identifier has a value bigger than 127, the encoding becomes a
        bit weird. The sub-identifiers are split into multiple sub-identifiers.
        """
        oid = Oid(1, 3, 6, 8072)
        result = bytes(oid)
        expected = b'\x06\x04\x2b\x06\xbf\x08'
        self.assertEqual(result, expected)

    def test_multibyte_decoding(self):
        """
        If a sub-identifier has a value bigger than 127, the decoding becomes a
        bit weird. The sub-identifiers are split into multiple sub-identifiers.
        """
        expected = Oid(1, 3, 6, 8072)
        result = Oid.from_bytes(b'\x06\x04\x2b\x06\xbf\x08')
        self.assertEqual(result, expected)

    def test_encode_large_value(self):
        """
        OID sub-identifiers larger than 127 must be split up.

        See https://en.wikipedia.org/wiki/Variable-length_quantity
        """
        result = Oid.encode_large_value(106903)
        expected = [0b10000110, 0b11000011, 0b00010111]
        self.assertEqual(result, expected)

    def test_pythonize(self):
        result = Oid(1, 2, 3).pythonize()
        expected = '1.2.3'
        self.assertEqual(result, expected)


class TestInteger(ByteTester):

    def test_encoding(self):
        value = Integer(100)
        result = bytes(value)
        expected = b'\x02\x01\x64'
        self.assertEqual(result, expected)

    def test_decoding(self):
        result = Integer.from_bytes(b'\x02\x01\x0a')
        expected = Integer(10)
        self.assertEqual(result, expected)

    def test_encoding_large_value(self):
        value = Integer(1913359423)
        result = bytes(value)
        expected = b"\x02\x04\x72\x0b\x8c\x3f"
        self.assertEqual(result, expected)

    def test_decoding_large_value(self):
        result = Integer.from_bytes(b"\x02\x04\x72\x0b\x8c\x3f")
        expected = Integer(1913359423)
        self.assertEqual(result, expected)

    def test_encoding_zero(self):
        value = Integer(0)
        result = bytes(value)
        expected = b"\x02\x01\x00"
        self.assertEqual(result, expected)

    def test_decoding_zero(self):
        result = Integer.from_bytes(b"\x02\x01\x00")
        expected = Integer(0)
        self.assertEqual(result, expected)

    def test_pythonize(self):
        result = Integer(1).pythonize()
        expected = 1
        self.assertEqual(result, expected)


class TestString(ByteTester):

    def test_encoding(self):
        value = String('hello')
        result = bytes(value)
        expected = b'\x04\x05hello'
        self.assertEqual(result, expected)

    def test_decoding(self):
        result = String.from_bytes(b'\x04\x05hello')
        expected = String('hello')
        self.assertEqual(result, expected)

    def test_pythonize(self):
        result = String("hello").pythonize()
        expected = "hello"
        self.assertEqual(result, expected)


class TestSequence(ByteTester):

    def test_encoding(self):
        value = Sequence(
            String('hello'),
            Oid(1, 3, 6),
            Integer(100)
        )
        result = bytes(value)
        expected = (
            bytes([
                Sequence.TAG,
                14,  # Expected length (note that an OID drops one byte)
            ]) +
            bytes(String('hello')) +
            bytes(Oid(1, 3, 6)) +
            bytes(Integer(100))
        )
        self.assertEqual(result, expected)

    def test_decoding_simple(self):
        result = Sequence.from_bytes(
            b'\x30\x0d'
            b'\x02\x01\x01'
            b'\x02\x01\x02'
            b'\x04\x03foo'
        )
        expected = Sequence(
            Integer(1),
            Integer(2),
            String('foo'),
        )
        self.assertEqual(result, expected)

    def test_decoding_recursive(self):
        result = Sequence.from_bytes(
            b'\x30\x17'
            b'\x02\x01\x01'
            b'\x02\x01\x02'
            b'\x04\x03foo'
            b'\x30\x08'
            b'\x02\x01\x01'
            b'\x02\x01\x02'
        )
        expected = Sequence(
            Integer(1),
            Integer(2),
            String('foo'),
            Sequence(
                Integer(1),
                Integer(2),
            )
        )
        self.assertEqual(result, expected)

    def test_pythonize(self):
        result = Sequence(Integer(1), Sequence(String('123'))).pythonize()
        expected = [1, ["123"]]
        self.assertEqual(result, expected)


class TestBasics(ByteTester):
    def test_decode_length_short(self):
        data = b'\x05'
        expected = 5
        result, data = consume_length(data)
        self.assertEqual(result, expected)
        self.assertEqual(data, b'')

    def test_decode_length_long(self):
        data = bytes([0b10000010, 0b00000001, 0b10110011])
        expected = 435
        result, data = consume_length(data)
        self.assertEqual(result, expected)
        self.assertEqual(data, b'')

    def test_decode_length_indefinite(self):
        with self.assertRaises(NotImplementedError):
            consume_length(bytes([0b10000000]))

    def test_decode_length_reserved(self):
        with self.assertRaises(NotImplementedError):
            consume_length(bytes([0b11111111]))

    def test_encode_length_short(self):
        expected = bytes([0b00100110])
        result = encode_length(38)
        self.assertEqual(result, expected)

    def test_encode_length_long(self):
        expected = bytes([0b10000001, 0b11001001])
        result = encode_length(201)
        self.assertEqual(result, expected)

    def test_encode_length_longer(self):
        expected = bytes([0b10000010, 0b00101110, 0b00000001])
        result = encode_length(302)
        self.assertBytesEqual(result, expected)

    def test_encode_length_indefinite(self):
        expected = bytes([0b10000000])
        result = encode_length(Length.INDEFINITE)
        self.assertBytesEqual(result, expected)

    test_identifier_univ_prim = make_identifier_test(
        0b00000010, TypeInfo.UNIVERSAL, TypeInfo.PRIMITIVE, 0b00010)

    test_identifier_univ_const = make_identifier_test(
        0b00100010, TypeInfo.UNIVERSAL, TypeInfo.CONSTRUCTED, 0b00010)

    test_identifier_app_prim = make_identifier_test(
        0b01000010, TypeInfo.APPLICATION, TypeInfo.PRIMITIVE, 0b00010)

    test_identifier_app_const = make_identifier_test(
        0b01100010, TypeInfo.APPLICATION, TypeInfo.CONSTRUCTED, 0b00010)

    test_identifier_ctx_prim = make_identifier_test(
        0b10000010, TypeInfo.CONTEXT, TypeInfo.PRIMITIVE, 0b00010)

    test_identifier_ctx_const = make_identifier_test(
        0b10100010, TypeInfo.CONTEXT, TypeInfo.CONSTRUCTED, 0b00010)

    test_identifier_prv_prim = make_identifier_test(
        0b11000010, TypeInfo.PRIVATE, TypeInfo.PRIMITIVE, 0b00010)

    test_identifier_prv_const = make_identifier_test(
        0b11100010, TypeInfo.PRIVATE, TypeInfo.CONSTRUCTED, 0b00010)

    def test_identifier_long(self):
        with self.assertRaises(NotImplementedError):
            TypeInfo.from_bytes(0b11111111)
