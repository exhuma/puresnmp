from ..x690.util import (
    TypeInfo,
)
from . import ByteTester


class TestTypeInfoDecoding(ByteTester):
    """
    Tests the various possible combinations for decoding type-hint octets into
    Python objects.
    """

    def test_from_bytes_a(self):
        result = TypeInfo.from_bytes(0b00011110)
        expected = TypeInfo(TypeInfo.UNIVERSAL, TypeInfo.PRIMITIVE, 0b11110)
        self.assertEqual(result, expected)

    def test_from_bytes_b(self):
        result = TypeInfo.from_bytes(0b00111110)
        expected = TypeInfo(TypeInfo.UNIVERSAL, TypeInfo.CONSTRUCTED, 0b11110)
        self.assertEqual(result, expected)

    def test_from_bytes_c(self):
        result = TypeInfo.from_bytes(0b01011110)
        expected = TypeInfo(TypeInfo.APPLICATION, TypeInfo.PRIMITIVE, 0b11110)
        self.assertEqual(result, expected)

    def test_from_bytes_d(self):
        result = TypeInfo.from_bytes(0b01111110)
        expected = TypeInfo(TypeInfo.APPLICATION, TypeInfo.CONSTRUCTED, 0b11110)
        self.assertEqual(result, expected)

    def test_from_bytes_e(self):
        result = TypeInfo.from_bytes(0b10011110)
        expected = TypeInfo(TypeInfo.CONTEXT, TypeInfo.PRIMITIVE, 0b11110)
        self.assertEqual(result, expected)

    def test_from_bytes_f(self):
        result = TypeInfo.from_bytes(0b10111110)
        expected = TypeInfo(TypeInfo.CONTEXT, TypeInfo.CONSTRUCTED, 0b11110)
        self.assertEqual(result, expected)

    def test_from_bytes_g(self):
        result = TypeInfo.from_bytes(0b11011110)
        expected = TypeInfo(TypeInfo.PRIVATE, TypeInfo.PRIMITIVE, 0b11110)
        self.assertEqual(result, expected)

    def test_from_bytes_h(self):
        result = TypeInfo.from_bytes(0b11111110)
        expected = TypeInfo(TypeInfo.PRIVATE, TypeInfo.CONSTRUCTED, 0b11110)
        self.assertEqual(result, expected)


class TestTypeInfoEncoding(ByteTester):
    """
    Tests the various possible combinations for encoding type-hint instances
    into bytes.
    """

    def test_to_bytes_a(self):
        obj = TypeInfo(TypeInfo.UNIVERSAL, TypeInfo.PRIMITIVE, 0b11110)
        result = bytes(obj)
        expected = bytes([0b00011110])
        self.assertEqual(result, expected)

    def test_to_bytes_b(self):
        obj = TypeInfo(TypeInfo.UNIVERSAL, TypeInfo.CONSTRUCTED, 0b11110)
        result = bytes(obj)
        expected = bytes([0b00111110])
        self.assertEqual(result, expected)

    def test_to_bytes_c(self):
        obj = TypeInfo(TypeInfo.APPLICATION, TypeInfo.PRIMITIVE, 0b11110)
        result = bytes(obj)
        expected = bytes([0b01011110])
        self.assertEqual(result, expected)

    def test_to_bytes_d(self):
        obj = TypeInfo(TypeInfo.APPLICATION, TypeInfo.CONSTRUCTED, 0b11110)
        result = bytes(obj)
        expected = bytes([0b01111110])
        self.assertEqual(result, expected)

    def test_to_bytes_e(self):
        obj = TypeInfo(TypeInfo.CONTEXT, TypeInfo.PRIMITIVE, 0b11110)
        result = bytes(obj)
        expected = bytes([0b10011110])
        self.assertEqual(result, expected)

    def test_to_bytes_f(self):
        obj = TypeInfo(TypeInfo.CONTEXT, TypeInfo.CONSTRUCTED, 0b11110)
        result = bytes(obj)
        expected = bytes([0b10111110])
        self.assertEqual(result, expected)

    def test_to_bytes_g(self):
        obj = TypeInfo(TypeInfo.PRIVATE, TypeInfo.PRIMITIVE, 0b11110)
        result = bytes(obj)
        expected = bytes([0b11011110])
        self.assertEqual(result, expected)

    def test_to_bytes_h(self):
        obj = TypeInfo(TypeInfo.PRIVATE, TypeInfo.CONSTRUCTED, 0b11110)
        result = bytes(obj)
        expected = bytes([0b11111110])
        self.assertEqual(result, expected)


class TestTypeInfoUtility(ByteTester):
    """
    Tests various "implied" functionality of TypeInfo objects.
    """

    def test_equality(self):
        a = TypeInfo(TypeInfo.UNIVERSAL, TypeInfo.CONSTRUCTED, 0b11110)
        b = TypeInfo(TypeInfo.UNIVERSAL, TypeInfo.CONSTRUCTED, 0b11110)
        self.assertEqual(a, b)

    def test_inequality(self):
        a = TypeInfo(TypeInfo.UNIVERSAL, TypeInfo.CONSTRUCTED, 0b11110)
        b = TypeInfo(TypeInfo.UNIVERSAL, TypeInfo.CONSTRUCTED, 0b10110)
        self.assertNotEqual(a, b)

    def test_encoding_symmetry_a(self):
        """
        Encoding an object to bytes, and then decoding the resulting bytes
        should yield the same instance.
        """
        expected = TypeInfo(TypeInfo.UNIVERSAL, TypeInfo.CONSTRUCTED, 0b11110)
        result = TypeInfo.from_bytes(bytes(expected))
        self.assertEqual(result, expected)

    def test_dencoding_symmetry_b(self):
        """
        Decoding an object from bytes, and then encoding the resulting instance
        should yield the same bytes.
        """
        expected = bytes([0b11111110])
        result = bytes(TypeInfo.from_bytes(expected))
        self.assertEqual(result, expected)
