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
        self.skipTest('TODO')

    def test_multibyte_encoding(self):
        """
        If a sub-identifier has a value bigger than 127, the encoding becomes a
        bit weird. The sub-identifiers are split into multiple sub-identifiers.
        """
        self.skipTest('TODO')

    def test_multibyte_decoding(self):
        """
        If a sub-identifier has a value bigger than 127, the decoding becomes a
        bit weird. The sub-identifiers are split into multiple sub-identifiers.
        """
        self.skipTest('TODO')


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


class TestString(unittest.TestCase):

    def test_encoding(self):
        value = String('hello')
        result = bytes(value)
        expected = b'\x04\x05hello'
        self.assertEqual(result, expected)

    def test_decoding(self):
        self.skipTest('TODO')


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

    def test_decoding(self):
        self.skipTest('TODO')
