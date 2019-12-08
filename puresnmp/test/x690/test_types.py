# -*- coding: utf8 -*-
# pylint: skip-file

import six
import sys

try:
    unicode
except NameError:
    unicode = str

from ...x690.util import TypeInfo
from ...x690.types import (
    Boolean,
    Integer,
    Null,
    ObjectIdentifier,
    OctetString,
    Sequence,
    T61String,
    Type,
    UnknownType,
    pop_tlv,
    to_bytes
)

from .. import ByteTester


class TestBoolean(ByteTester):

    def test_encoding_false(self):
        value = Boolean(False)
        result = to_bytes(value)
        expected = b'\x01\x01\x00'
        self.assertBytesEqual(result, expected)

    def test_encoding_true(self):
        value = Boolean(True)
        result = to_bytes(value)
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
        with six.assertRaisesRegex(self, ValueError, 'Length'):
            Boolean.validate(b'\x01\x00\x00')


class TestObjectIdentifier(ByteTester):

    def setUp(self):
        super(TestObjectIdentifier, self).setUp()
        self.maxDiff = None

    def test_simple_encoding(self):
        """
        A simple OID with no identifier above 127
        """
        oid = ObjectIdentifier(1, 3, 6, 1, 2, 1)
        result = to_bytes(oid)
        expected = b'\x06\x05\x2b\x06\x01\x02\x01'
        self.assertBytesEqual(result, expected)

    def test_simple_decoding(self):
        """
        A simple OID with no identifier above 127
        """
        expected = ObjectIdentifier(1, 3, 6, 1, 2, 1)
        result = ObjectIdentifier.from_bytes(b'\x06\x05\x2b\x06\x01\x02\x01')
        self.assertEqual(result, expected)

    def test_decoding_zero(self):
        """
        A simple OID with the top-level ID '0'
        """
        expected = ObjectIdentifier(0)
        result = ObjectIdentifier.from_bytes(b'\x06\x00')
        self.assertEqual(result, expected)

    def test_encoding_zero(self):
        """
        A simple OID with the top-level ID '0'
        """
        oid = ObjectIdentifier(0)
        result = to_bytes(oid)
        expected = b'\x06\x00'
        self.assertEqual(result, expected)

    def test_multibyte_encoding(self):
        """
        If a sub-identifier has a value bigger than 127, the encoding becomes a
        bit weird. The sub-identifiers are split into multiple sub-identifiers.
        """
        oid = ObjectIdentifier(1, 3, 6, 8072)
        result = to_bytes(oid)
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

    def test_fromstring_leading_dot(self):
        '''
        A leading dot represents the "root" node. This should be allowed as
        string input.
        '''
        result = ObjectIdentifier.from_string('.1.2.3')
        expected = ObjectIdentifier(1, 2, 3)
        self.assertEqual(result, expected)

    def test_pythonize(self):
        result = ObjectIdentifier(1, 2, 3).pythonize()
        expected = '1.2.3'
        self.assertEqual(result, expected)

    def test_str(self):
        result = unicode(ObjectIdentifier(1, 2, 3))
        expected = '1.2.3'
        self.assertEqual(result, expected)

    def test_encode_root(self):
        result = to_bytes(ObjectIdentifier(1))
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

    def test_length_1(self):
        '''
        OIDs with one node should have a length of 1
        '''
        obj = ObjectIdentifier(1)
        self.assertEqual(len(obj), 1)

    def test_length_ge1(self):
        '''
        OIDs with more than one node should have a length equal to the number
        of nodes.
        '''
        obj = ObjectIdentifier(1, 2, 3)
        self.assertEqual(len(obj), 3)

    def test_inequalitites(self):
        a = ObjectIdentifier(1, 2, 3)
        b = ObjectIdentifier(1, 2, 4)
        self.assertTrue(a < b)
        self.assertFalse(b < a)
        self.assertFalse(a < a)
        self.assertFalse(a > b)
        self.assertTrue(b > a)
        self.assertFalse(b > b)

    def test_concatenation(self):
        a = ObjectIdentifier(1, 2, 3)
        b = ObjectIdentifier(4, 5, 6)
        expected = ObjectIdentifier(1, 2, 3, 4, 5, 6)
        result = a + b
        self.assertEqual(result, expected)

    def test_item_access(self):
        a = ObjectIdentifier(1, 2, 3)
        expected = ObjectIdentifier(2)
        result = a[1]
        self.assertEqual(result, expected)


class TestInteger(ByteTester):

    def test_encoding(self):
        value = Integer(100)
        result = to_bytes(value)
        expected = b'\x02\x01\x64'
        self.assertBytesEqual(result, expected)

    def test_decoding(self):
        result = Integer.from_bytes(b'\x02\x01\x0a')
        expected = Integer(10)
        self.assertEqual(result, expected)

    def test_encoding_large_value(self):
        value = Integer(1913359423)
        result = to_bytes(value)
        expected = b"\x02\x04\x72\x0b\x8c\x3f"
        self.assertBytesEqual(result, expected)

    def test_decoding_large_value(self):
        result = Integer.from_bytes(b"\x02\x04\x72\x0b\x8c\x3f")
        expected = Integer(1913359423)
        self.assertEqual(result, expected)

    def test_encoding_zero(self):
        value = Integer(0)
        result = to_bytes(value)
        expected = b"\x02\x01\x00"
        self.assertBytesEqual(result, expected)

    def test_decoding_zero(self):
        result = Integer.from_bytes(b"\x02\x01\x00")
        expected = Integer(0)
        self.assertEqual(result, expected)

    def test_decoding_minus_one(self):
        result = Integer.from_bytes(b"\x02\x01\xff")
        expected = Integer(-1)
        self.assertEqual(result, expected)

    def test_decoding_minus_large_value(self):
        result = Integer.from_bytes(b"\x02\x04\x8d\xf4\x73\xc1")
        expected = Integer(-1913359423)
        self.assertEqual(result, expected)

    def test_pythonize(self):
        result = Integer(1).pythonize()
        expected = 1
        self.assertEqual(result, expected)


class TestIntegerValues(ByteTester):

    def test_32768(self):
        """
        Issue identified in github issue #27

        See https://github.com/exhuma/puresnmp/issues/27
        """
        value = Integer(32768)
        result = to_bytes(value)
        expected = b'\x02\x03\x00\x80\x00'
        self.assertBytesEqual(result, expected)

    def test_minus_one(self):
        value = Integer(-1)
        result = to_bytes(value)
        expected = b'\x02\x01\xff'
        self.assertBytesEqual(result, expected)

    def test_minus_two(self):
        value = Integer(-2)
        result = to_bytes(value)
        expected = b'\x02\x01\xfe'
        self.assertBytesEqual(result, expected)

    def test_zero(self):
        value = Integer(0)
        result = to_bytes(value)
        expected = b'\x02\x01\x00'
        self.assertBytesEqual(result, expected)

    def test_minus_16bit(self):
        value = Integer(-0b1111111111111111)
        result = to_bytes(value)
        expected = b'\x02\x03\xff\x00\x01'
        self.assertBytesEqual(result, expected)

    def test_minus_16bit_plus_one(self):
        value = Integer(-0b1111111111111111 + 1)
        result = to_bytes(value)
        expected = b'\x02\x03\xff\x00\x02'
        self.assertBytesEqual(result, expected)

    def test_minus_16bit_minus_one(self):
        value = Integer(-0b1111111111111111 - 1)
        result = to_bytes(value)
        expected = b'\x02\x03\xff\x00\x00'
        self.assertBytesEqual(result, expected)

    def test_minus_16bit_minus_two(self):
        value = Integer(-0b1111111111111111 - 2)
        result = to_bytes(value)
        expected = b'\x02\x03\xfe\xff\xff'
        self.assertBytesEqual(result, expected)

    def test_16bit(self):
        value = Integer(0b1111111111111111)
        result = to_bytes(value)
        expected = b'\x02\x03\x00\xff\xff'
        self.assertBytesEqual(result, expected)

    def test_16bitplusone(self):
        value = Integer(0b1111111111111111 + 1)
        result = to_bytes(value)
        expected = b'\x02\x03\x01\x00\x00'
        self.assertBytesEqual(result, expected)

    def test_16bitminusone(self):
        value = Integer(0b1111111111111111 - 1)
        result = to_bytes(value)
        expected = b'\x02\x03\x00\xff\xfe'
        self.assertBytesEqual(result, expected)

    def test_32bit(self):
        value = Integer(0b11111111111111111111111111111111)
        result = to_bytes(value)
        expected = b'\x02\x05\x00\xff\xff\xff\xff'
        self.assertBytesEqual(result, expected)


class TestOctetString(ByteTester):

    def test_encoding(self):
        value = OctetString('hello')
        result = to_bytes(value)
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


class TestT61String(ByteTester):

    def test_encoding(self):
        value = T61String(u'hello Ω')
        result = to_bytes(value)
        expected = b'\x14\x07hello \xe0'
        self.assertBytesEqual(result, expected)

    def test_decoding(self):
        result = T61String.from_bytes(b'\x14\x07hello \xe0')
        expected = T61String(u'hello Ω')
        self.assertEqual(result, expected)

    def test_pythonize_from_string(self):
        obj = T61String(u"hello Ω")
        result = obj.pythonize()
        expected = u"hello Ω"
        self.assertEqual(result, expected)

    def test_pythonize_from_bytes(self):
        obj = T61String(b"hello \xe0")
        result = obj.pythonize()
        expected = u"hello Ω"
        self.assertEqual(result, expected)


class TestSequence(ByteTester):

    def test_encoding(self):
        value = Sequence(
            OctetString('hello'),
            ObjectIdentifier(1, 3, 6),
            Integer(100)
        )
        result = to_bytes(value)
        expected = (
            to_bytes([
                0x30,
                14,  # Expected length (note that an OID drops one byte)
            ]) +
            to_bytes(OctetString('hello')) +
            to_bytes(ObjectIdentifier(1, 3, 6)) +
            to_bytes(Integer(100))
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

    def test_length_empty(self):
        result = len(Sequence())
        expected = 0
        self.assertEqual(result, expected)

    def test_length_nonempty(self):
        result = len(Sequence(Integer(1), Integer(2)))
        expected = 2
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
        result = to_bytes(Null())
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


class TestUnknownType(ByteTester):

    def test_null_from_bytes(self):
        result = UnknownType.from_bytes(b'')
        expected = Null()
        self.assertEqual(result, expected)

    def test_decoding(self):
        result, _ = pop_tlv(b'\x99\x01\x0a')
        expected = UnknownType(0x99, b'\x0a')
        self.assertEqual(result, expected)

    def test_encoding(self):
        result = to_bytes(UnknownType(0x99, b'\x0a'))
        expected = b'\x99\x01\x0a'
        self.assertEqual(result, expected)

    def test_decoding_corrupt_length(self):
        with six.assertRaisesRegex(self, ValueError, 'length'):
            UnknownType.from_bytes(b'\x99\x02\x0a')

    def test_repr(self):
        result = repr(UnknownType(99, b'abc'))
        typeinfo = TypeInfo(u'application', u'constructed', 3)
        if not six.PY2:
            expected = "UnknownType(99, b'abc', typeinfo=%r)" % (typeinfo,)
        else:
            expected = "UnknownType(99, 'abc', typeinfo=%r)" % (typeinfo,)
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
        result = pop_tlv(to_bytes([2, 1, 0]))
        expected = (Integer(0), b'')
        self.assertEqual(result, expected)

    def test_tlv_unknown_type(self):
        result = pop_tlv(to_bytes([254, 1, 0]))
        expected = (UnknownType(254, b'\x00'), b'')
        self.assertEqual(result, expected)
        self.assertEqual(result[0].tag, 254)
        self.assertEqual(result[0].length, 1)
        self.assertEqual(result[0].value, b'\x00')

    def test_validation_wrong_typeclass(self):
        with self.assertRaises(ValueError):
            Integer.validate(to_bytes([0b00111110]))

    def test_null_from_bytes(self):
        result = Type.from_bytes(b'')
        expected = Null()
        self.assertEqual(result, expected)

    def test_corrupt_length(self):
        with six.assertRaisesRegex(self, ValueError, 'length'):
            Integer.from_bytes(b'\x02\x01\x01\x01')

    def test_repr(self):
        obj = Type()
        obj.value = 10
        result = repr(obj)
        expected = 'Type(10)'
        self.assertEqual(result, expected)

    def test_childof(self):
        a = ObjectIdentifier(1, 2, 3)
        b = ObjectIdentifier(1, 2, 3, 1)
        c = ObjectIdentifier(1, 2, 4)
        d = ObjectIdentifier(1)
        self.assertTrue(b.childof(a))
        self.assertFalse(a.childof(b))
        self.assertTrue(a.childof(a))
        self.assertFalse(c.childof(a))
        self.assertFalse(a.childof(c))
        self.assertFalse(d.childof(c))
        self.assertTrue(c.childof(d))

    def test_parentdf(self):
        a = ObjectIdentifier(1, 2, 3)
        b = ObjectIdentifier(1, 2, 3, 1)
        c = ObjectIdentifier(1, 2, 4)
        d = ObjectIdentifier(1)
        self.assertFalse(b.parentof(a))
        self.assertTrue(a.parentof(b))
        self.assertTrue(a.parentof(a))
        self.assertFalse(c.parentof(a))
        self.assertFalse(a.parentof(c))
        self.assertTrue(d.parentof(c))
        self.assertFalse(c.parentof(d))
