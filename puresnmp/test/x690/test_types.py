from ...x690.types import (
    Boolean,
    Integer,
    NonASN1Type,
    Null,
    ObjectIdentifier,
    OctetString,
    Sequence,
    Type,
    pop_tlv,
)

from .. import ByteTester


class TestBoolean(ByteTester):

    def test_encoding_false(self):
        value = Boolean(False)
        result = bytes(value)
        expected = b'\x01\x01\x00'
        self.assertBytesEqual(result, expected)

    def test_encoding_true(self):
        value = Boolean(True)
        result = bytes(value)
        expected = b'\x01\x01\x01'
        self.assertBytesEqual(result, expected)

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

    def test_validate_too_long(self):
        """
        Validate what happens when there are too many bytes.
        """
        with self.assertRaisesRegexp(ValueError, 'Length'):
            Boolean.validate(b'\x01\x00\x00')


class TestObjectIdentifier(ByteTester):

    def setUp(self):
        super().setUp()
        self.maxDiff = None

    def test_simple_encoding(self):
        """
        A simple OID with no identifier above 127
        """
        oid = ObjectIdentifier(1, 3, 6, 1, 2, 1)
        result = bytes(oid)
        expected = b'\x06\x05\x2b\x06\x01\x02\x01'
        self.assertBytesEqual(result, expected)

    def test_simple_decoding(self):
        """
        A simple OID with no identifier above 127
        """
        expected = ObjectIdentifier(1, 3, 6, 1, 2, 1)
        result = ObjectIdentifier.from_bytes(b'\x06\x05\x2b\x06\x01\x02\x01')
        self.assertEqual(result, expected)

    def test_multibyte_encoding(self):
        """
        If a sub-identifier has a value bigger than 127, the encoding becomes a
        bit weird. The sub-identifiers are split into multiple sub-identifiers.
        """
        oid = ObjectIdentifier(1, 3, 6, 8072)
        result = bytes(oid)
        expected = b'\x06\x04\x2b\x06\xbf\x08'
        self.assertBytesEqual(result, expected)

    def test_multibyte_decoding(self):
        """
        If a sub-identifier has a value bigger than 127, the decoding becomes a
        bit weird. The sub-identifiers are split into multiple sub-identifiers.
        """
        expected = ObjectIdentifier(1, 3, 6, 8072)
        result = ObjectIdentifier.from_bytes(b'\x06\x04\x2b\x06\xbf\x08')
        self.assertEqual(result, expected)

    def test_encode_large_value(self):
        """
        OID sub-identifiers larger than 127 must be split up.

        See https://en.wikipedia.org/wiki/Variable-length_quantity
        """
        result = ObjectIdentifier.encode_large_value(106903)
        expected = [0b10000110, 0b11000011, 0b00010111]
        self.assertEqual(result, expected)

    def test_fromstring(self):
        result = ObjectIdentifier.from_string('1.2.3')
        expected = ObjectIdentifier(1, 2, 3)
        self.assertEqual(result, expected)

    def test_pythonize(self):
        result = ObjectIdentifier(1, 2, 3).pythonize()
        expected = '1.2.3'
        self.assertEqual(result, expected)

    def test_str(self):
        result = str(ObjectIdentifier(1, 2, 3))
        expected = '1.2.3'
        self.assertEqual(result, expected)

    def test_encode_root(self):
        result = bytes(ObjectIdentifier(1))
        expected = b'\x06\x01\x01'
        self.assertBytesEqual(result, expected)

    def test_construct_root_from_string(self):
        """
        Using "." to denote the root OID is common. We should allow this.
        """
        result = ObjectIdentifier.from_string('.')
        expected = ObjectIdentifier(1)
        self.assertEqual(result, expected)

    def test_containment_a(self):
        a = ObjectIdentifier.from_string('1.2.3.4')
        b = ObjectIdentifier.from_string('1.2.3')
        self.assertTrue(a in b)

    def test_containment_b(self):
        a = ObjectIdentifier.from_string('1.2.3.4')
        b = ObjectIdentifier.from_string('1.2.3.4')
        self.assertTrue(a in b)

    def test_containment_c(self):
        a = ObjectIdentifier.from_string('1.3.6.1.2.1.1.1.0')
        b = ObjectIdentifier.from_string('1.3.6.1.2.1')
        self.assertTrue(a in b)

    def test_non_containment_a(self):
        a = ObjectIdentifier.from_string('1.2.3')
        b = ObjectIdentifier.from_string('1.2.3.4')
        self.assertFalse(a in b)

    def test_non_containment_b(self):
        a = ObjectIdentifier.from_string('1.2.3.5')
        b = ObjectIdentifier.from_string('1.2.3.4')
        self.assertFalse(a in b)

    def test_non_containment_c(self):
        a = ObjectIdentifier.from_string('1.2.3.4')
        b = ObjectIdentifier.from_string('1.2.3.5')
        self.assertFalse(a in b)

    def test_non_containment_d(self):
        a = ObjectIdentifier.from_string('1.3.6.1.2.1.25.1.1.0')
        b = ObjectIdentifier.from_string('1.3.6.1.2.1.1.9')
        self.assertFalse(a in b)

    def test_non_containment_e(self):
        a = ObjectIdentifier.from_string('1.3.6.1.2.13')
        b = ObjectIdentifier.from_string('1.3.6.1.2.1')
        self.assertFalse(a in b)

    def test_create_by_iterable(self):
        result = ObjectIdentifier(['1', '2', '3'])
        expected = ObjectIdentifier(1, 2, 3)
        self.assertEqual(result, expected)

    def test_repr(self):
        result = repr(ObjectIdentifier(['1', '2', '3']))
        expected = 'ObjectIdentifier((1, 2, 3))'
        self.assertEqual(result, expected)

    def test_hash(self):
        """
        Test hash function and that it makes sense.
        """
        result = hash(ObjectIdentifier(['1', '2', '3']))
        expected = hash(ObjectIdentifier(1, 2, 3))
        self.assertEqual(result, expected)

    def test_non_containment_f(self):
        """
        This case showed up during development of bulk operations. Throwing it
        into the unit tests to ensure proper containment checks.
        """
        a = ObjectIdentifier(1, 3, 6, 1, 2, 1, 2, 2, 1, 22)
        b = ObjectIdentifier(1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 38)
        self.assertNotIn(a, b, '%s should not be in %s' % (a, b))
        self.assertNotIn(b, a, '%s should not be in %s' % (b, a))


class TestInteger(ByteTester):

    def test_encoding(self):
        value = Integer(100)
        result = bytes(value)
        expected = b'\x02\x01\x64'
        self.assertBytesEqual(result, expected)

    def test_decoding(self):
        result = Integer.from_bytes(b'\x02\x01\x0a')
        expected = Integer(10)
        self.assertEqual(result, expected)

    def test_encoding_large_value(self):
        value = Integer(1913359423)
        result = bytes(value)
        expected = b"\x02\x04\x72\x0b\x8c\x3f"
        self.assertBytesEqual(result, expected)

    def test_decoding_large_value(self):
        result = Integer.from_bytes(b"\x02\x04\x72\x0b\x8c\x3f")
        expected = Integer(1913359423)
        self.assertEqual(result, expected)

    def test_encoding_zero(self):
        value = Integer(0)
        result = bytes(value)
        expected = b"\x02\x01\x00"
        self.assertBytesEqual(result, expected)

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
        value = OctetString('hello')
        result = bytes(value)
        expected = b'\x04\x05hello'
        self.assertBytesEqual(result, expected)

    def test_decoding(self):
        result = OctetString.from_bytes(b'\x04\x05hello')
        expected = OctetString('hello')
        self.assertEqual(result, expected)

    def test_pythonize(self):
        result = OctetString("hello").pythonize()
        expected = b"hello"
        self.assertEqual(result, expected)


class TestSequence(ByteTester):

    def test_encoding(self):
        value = Sequence(
            OctetString('hello'),
            ObjectIdentifier(1, 3, 6),
            Integer(100)
        )
        result = bytes(value)
        expected = (
            bytes([
                0x30,
                14,  # Expected length (note that an OID drops one byte)
            ]) +
            bytes(OctetString('hello')) +
            bytes(ObjectIdentifier(1, 3, 6)) +
            bytes(Integer(100))
        )
        self.assertBytesEqual(result, expected)

    def test_decoding_simple(self):
        result = Sequence.from_bytes(
            b'\x30\x0b'
            b'\x02\x01\x01'
            b'\x02\x01\x02'
            b'\x04\x03foo'
        )
        expected = Sequence(
            Integer(1),
            Integer(2),
            OctetString('foo'),
        )
        self.assertEqual(result, expected)

    def test_decoding_recursive(self):
        result = Sequence.from_bytes(
            b'\x30\x13'
            b'\x02\x01\x01'
            b'\x02\x01\x02'
            b'\x04\x03foo'
            b'\x30\x06'
            b'\x02\x01\x01'
            b'\x02\x01\x02'
        )
        expected = Sequence(
            Integer(1),
            Integer(2),
            OctetString('foo'),
            Sequence(
                Integer(1),
                Integer(2),
            )
        )
        self.assertEqual(result, expected)

    def test_pythonize(self):
        result = Sequence(Integer(1), Sequence(OctetString('123'))).pythonize()
        expected = [1, [b"123"]]
        self.assertEqual(result, expected)

    def test_iteration(self):
        data = Sequence(
            Integer(1),
            Sequence(OctetString('123')),
            OctetString(b'foo')
        )
        result = [item for item in data]
        expected = [
            Integer(1),
            Sequence(OctetString('123')),
            OctetString(b'foo')
        ]
        self.assertEqual(result, expected)

    def test_indexing(self):
        data = Sequence(
            Integer(1),
            OctetString(b'foo')
        )
        result = data[1]
        expected = OctetString(b'foo')
        self.assertEqual(result, expected)

    def test_repr(self):
        result = repr(Sequence(Integer(10)))
        expected = 'Sequence(Integer(10))'
        self.assertEqual(result, expected)


class TestNull(ByteTester):

    def test_null_is_false(self):
        """
        The Null type should be considered as falsy.
        """
        self.assertFalse(Null())

    def test_validate_true(self):
        Null.validate(b'\x05\x00')

    def test_validate_false(self):
        with self.assertRaises(ValueError):
            Null.validate(b'\x05\x01')

    def test_encoding(self):
        result = bytes(Null())
        expected = b'\x05\x00'
        self.assertEqual(result, expected)

    def test_decode_null(self):
        expected = Null()
        result = Null.decode('\x05\x00\x00')
        self.assertEqual(result, expected)

    def test_repr(self):
        expected = 'Null()'
        result = repr(Null())
        self.assertEqual(result, expected)


class TestNonASN1Type(ByteTester):

    def test_null_from_bytes(self):
        result = NonASN1Type.from_bytes(b'')
        expected = Null()
        self.assertEqual(result, expected)

    def test_decoding(self):
        result, _ = pop_tlv(b'\x99\x01\x0a')
        expected = NonASN1Type(0x99, b'\x0a')
        self.assertEqual(result, expected)

    def test_encoding(self):
        result = bytes(NonASN1Type(0x99, b'\x0a'))
        expected = b'\x99\x01\x0a'
        self.assertEqual(result, expected)

    def test_decoding_corrupt_length(self):
        with self.assertRaisesRegexp(ValueError, 'length'):
            NonASN1Type.from_bytes(b'\x99\x02\x0a')

    def test_repr(self):
        result = repr(NonASN1Type(99, b'abc'))
        expected = "NonASN1Type(99, b'abc')"
        self.assertEqual(result, expected)


class TestAllTypes(ByteTester):
    """
    Tests which are valid for all types
    """

    def test_tlv_null(self):
        result = pop_tlv(b'')
        expected = (Null(), b'')
        self.assertEqual(result, expected)

    def test_tlv_simple(self):
        result = pop_tlv(bytes([2, 1, 0]))
        expected = (Integer(0), b'')
        self.assertEqual(result, expected)

    def test_tlv_unknown_type(self):
        result = pop_tlv(bytes([254, 1, 0]))
        expected = (NonASN1Type(254, b'\x00'), b'')
        self.assertEqual(result, expected)
        self.assertEqual(result[0].tag, 254)
        self.assertEqual(result[0].length, 1)
        self.assertEqual(result[0].value, b'\x00')

    def test_validation_wrong_typeclass(self):
        with self.assertRaises(ValueError):
            Integer.validate(bytes([0b00111110]))

    def test_null_from_bytes(self):
        result = Type.from_bytes(b'')
        expected = Null()
        self.assertEqual(result, expected)

    def test_corrupt_length(self):
        with self.assertRaisesRegexp(ValueError, 'length'):
            Integer.from_bytes(b'\x02\x01\x01\x01')

    def test_repr(self):
        obj = Type()
        obj.value = 10
        result = repr(obj)
        expected = 'Type(10)'
        self.assertEqual(result, expected)
