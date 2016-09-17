from ...x690.types import ObjectIdentifier
from ...x690.util import (
    Length,
    TypeInfo,
    decode_length,
    encode_length,
    tablify,
    visible_octets,
)
from .. import ByteTester


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


class TestTypeInfoClass(ByteTester):
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

    def test_impossible_class(self):
        instance = TypeInfo(10, 100, 1000)
        with self.assertRaisesRegexp(ValueError, 'class'):
            bytes(instance)

    def test_impossible_pc(self):
        instance = TypeInfo(TypeInfo.APPLICATION, 100, 1000)
        with self.assertRaisesRegexp(ValueError, 'primitive/constructed'):
            bytes(instance)


class TestLengthOctets(ByteTester):

    def test_encode_length_short(self):
        expected = bytes([0b00100110])
        result = encode_length(38)
        self.assertEqual(result, expected)

    def test_encode_length_long(self):
        expected = bytes([0b10000001, 0b11001001])
        result = encode_length(201)
        self.assertBytesEqual(result, expected)

    def test_encode_length_longer(self):
        expected = bytes([0b10000010, 0b00101110, 0b00000001])
        result = encode_length(302)
        self.assertBytesEqual(result, expected)

    def test_encode_length_longer_2(self):
        expected = bytes([0x81, 0xa4])
        result = encode_length(164)
        self.assertBytesEqual(result, expected)

    def test_encode_length_indefinite(self):
        expected = bytes([0b10000000])
        result = encode_length(Length.INDEFINITE)
        self.assertBytesEqual(result, expected)

    def test_identifier_long(self):
        with self.assertRaises(NotImplementedError):
            TypeInfo.from_bytes(0b11111111)
        self.skipTest('Not yet implemented')  # TODO implement

    def test_decode_length_short(self):
        data = b'\x05'
        expected = 5
        result, data = decode_length(data)
        self.assertEqual(result, expected)
        self.assertEqual(data, b'')

    def test_decode_length_long(self):
        data = bytes([0b10000010, 0b00000001, 0b10110011])
        expected = 435
        result, data = decode_length(data)
        self.assertEqual(result, expected)
        self.assertEqual(data, b'')

    def test_decode_length_longer(self):
        data = bytes([0x81, 0xa4])
        expected = 164
        result, data = decode_length(data)
        self.assertEqual(result, expected)
        self.assertEqual(data, b'')

    def test_decode_length_indefinite(self):
        with self.assertRaises(NotImplementedError):
            decode_length(bytes([0b10000000]))

    def test_decode_length_reserved(self):
        with self.assertRaises(NotImplementedError):
            decode_length(bytes([0b11111111]))


class TestHelpers(ByteTester):

    def test_visible_octets_minimal(self):
        result = visible_octets(bytes([0b00000000, 0b01010101]))
        expected = '00 55                                              .U'
        self.assertEqual(result, expected)

    def test_visible_octets_double_space(self):
        """
        Test that we have a double space after 8 octets for better readability
        """
        result = visible_octets(bytes([
            0b00000000,
            0b01010101,
            0b00000000,
            0b01010101,
            0b00000000,
            0b01010101,
            0b00000000,
            0b01010101,
            0b01010101,
        ]))
        expected = ('00 55 00 55 00 55 00 55  55                        '
                    '.U.U.U.UU')
        self.assertEqual(result, expected)

    def test_visible_octets_multiline(self):
        """
        If we have more than 16 octets, we need to go to a new line.
        """
        result = visible_octets(bytes([0b00000000, 0b01010101] * 9))
        expected = ('00 55 00 55 00 55 00 55  00 55 00 55 00 55 00 55   '
                    '.U.U.U.U.U.U.U.U\n'
                    '00 55                                              '
                    '.U')
        self.assertEqual(result, expected)

    def test_tablify_simple(self):
        data = [
            (ObjectIdentifier.from_string('1.2.1.1'), 'row 1 col 1'),
            (ObjectIdentifier.from_string('1.2.1.2'), 'row 2 col 1'),
            (ObjectIdentifier.from_string('1.2.2.1'), 'row 1 col 2'),
            (ObjectIdentifier.from_string('1.2.2.2'), 'row 2 col 2'),
        ]
        result = tablify(data)
        expected = [
            {'0': '1',
             '1': 'row 1 col 1',
             '2': 'row 1 col 2'},
            {'0': '2',
             '1': 'row 2 col 1',
             '2': 'row 2 col 2'},
        ]
        self.assertCountEqual(result, expected)

    def test_tablify_with_base(self):
        """
        Sometimes, the row indices are actually OIDs, so we need a way to "cut"
        these off.
        """
        data = [
            (ObjectIdentifier.from_string('1.2.1.1.1.1'), 'row 1.1.1 col 1'),
            (ObjectIdentifier.from_string('1.2.1.2.1.1'), 'row 2.1.1 col 1'),
            (ObjectIdentifier.from_string('1.2.2.1.1.1'), 'row 1.1.1 col 2'),
            (ObjectIdentifier.from_string('1.2.2.2.1.1'), 'row 2.1.1 col 2'),
        ]
        result = tablify(data, num_base_nodes=2)
        expected = [
            {'0': '1.1.1',
             '1': 'row 1.1.1 col 1',
             '2': 'row 1.1.1 col 2'},
            {'0': '2.1.1',
             '1': 'row 2.1.1 col 1',
             '2': 'row 2.1.1 col 2'},
        ]
        self.assertCountEqual(result, expected)

    def test_tmp(self):
        data = [
            (ObjectIdentifier.from_string('1.2.1.5.10'), 'row 5.10 col 1'),
            (ObjectIdentifier.from_string('1.2.1.6.10'), 'row 6.10 col 1'),
            (ObjectIdentifier.from_string('1.2.2.5.10'), 'row 5.10 col 2'),
            (ObjectIdentifier.from_string('1.2.2.6.10'), 'row 6.10 col 2'),
        ]
        result = tablify(data, num_base_nodes=2)
        expected = [
            {'0': '5.10', '1': 'row 5.10 col 1', '2': 'row 5.10 col 2'},
            {'0': '6.10', '1': 'row 6.10 col 1', '2': 'row 6.10 col 2'},
        ]
        self.assertCountEqual(result, expected)
