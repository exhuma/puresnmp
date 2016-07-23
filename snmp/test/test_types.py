import unittest

from ..marshal import Oid, List, Integer, String


class TestOid(unittest.TestCase):

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


class TestInteger(unittest.TestCase):

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


class TestString(unittest.TestCase):

    def test_encoding(self):
        value = String('hello')
        result = bytes(value)
        expected = b'\x04\x05hello'
        self.assertEqual(result, expected)

    def test_decoding(self):
        result = String.from_bytes(b'\x04\x05hello')
        expected = String('hello')
        self.assertEqual(result, expected)


class TestList(unittest.TestCase):

    def test_encoding(self):
        value = List(
            String('hello'),
            Oid(1, 3, 6),
            Integer(100)
        )
        result = bytes(value)
        expected = (
            bytes([
                List.HEADER,
                14,  # Expected length (note that an OID drops one byte)
            ]) +
            bytes(String('hello')) +
            bytes(Oid(1, 3, 6)) +
            bytes(Integer(100)) +
            bytes([0x05, 0x00])  # NULL (end of list)
        )
        self.assertEqual(result, expected)

    def test_decoding_simple(self):
        result = List.from_bytes(
            b'\x30\x0d'
            b'\x02\x01\x01'
            b'\x02\x01\x02'
            b'\x04\x03foo'
            b'\x05\x00'
        )
        expected = List(
            Integer(1),
            Integer(2),
            String('foo'),
        )
        self.assertEqual(result, expected)

    def test_decoding_recursive(self):
        result = List.from_bytes(
            b'\x30\x17'
            b'\x02\x01\x01'
            b'\x02\x01\x02'
            b'\x04\x03foo'
            b'\x30\x08'
            b'\x02\x01\x01'
            b'\x02\x01\x02'
            b'\x05\x00'
            b'\x05\x00'
        )
        expected = List(
            Integer(1),
            Integer(2),
            String('foo'),
            List(
                Integer(1),
                Integer(2),
            )
        )
        self.assertEqual(result, expected)
