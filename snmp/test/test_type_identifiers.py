from ..x690 import types as t
from ..x690.types import TypeInfo

from . import ByteTester


def make_identifier_test(octet, expected_class, expected_pc, expected_value):
    def fun(self):
        result = TypeInfo.from_bytes(octet)
        expected = TypeInfo(expected_class, expected_pc, expected_value)
        self.assertEqual(result, expected)
    return fun


def add_class_detector(cls, expected_class, pc, tag, name=None):
    def fun(inst):
        result = t.Registry.get(TypeInfo.UNIVERSAL, tag)
        inst.assertEqual(result, expected_class)
    fun.__name__ = 'test_%s' % expected_class.__name__
    setattr(cls, 'test_%s' % expected_class.__name__, fun)


class TestBasics(ByteTester):

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
        self.skipTest('This is not yet implemented. I have not understood the '
                      'spec to confidently write a test')  # TODO


class TestClassDetector(ByteTester):
    pass


add_class_detector(TestClassDetector, t.EOC, TypeInfo.PRIMITIVE, 0x00, 'End-of-Content (EOC)')
add_class_detector(TestClassDetector, t.Boolean, TypeInfo.PRIMITIVE, 0x01)
add_class_detector(TestClassDetector, t.Integer, TypeInfo.PRIMITIVE, 0x02)
add_class_detector(TestClassDetector, t.BitString , TypeInfo.PRIMITIVE, 0x03)
add_class_detector(TestClassDetector, t.BitString , TypeInfo.CONSTRUCTED, 0x03)
add_class_detector(TestClassDetector, t.OctetString , TypeInfo.PRIMITIVE, 0x04)
add_class_detector(TestClassDetector, t.OctetString , TypeInfo.CONSTRUCTED, 0x04)
add_class_detector(TestClassDetector, t.Null, TypeInfo.PRIMITIVE, 0x05)
add_class_detector(TestClassDetector, t.ObjectIdentifier, TypeInfo.PRIMITIVE, 0x06)
add_class_detector(TestClassDetector, t.ObjectDescriptor, TypeInfo.PRIMITIVE, 0x07)
add_class_detector(TestClassDetector, t.ObjectDescriptor, TypeInfo.CONSTRUCTED, 0x07)
add_class_detector(TestClassDetector, t.External, TypeInfo.CONSTRUCTED, 0x08)
add_class_detector(TestClassDetector, t.Real, TypeInfo.PRIMITIVE, 0x09, 'REAL (float)')
add_class_detector(TestClassDetector, t.Enumerated, TypeInfo.PRIMITIVE, 0x0A)
add_class_detector(TestClassDetector, t.EmbeddedPdv, TypeInfo.CONSTRUCTED, 0x0B)
add_class_detector(TestClassDetector, t.Utf8String , TypeInfo.PRIMITIVE, 0x0C)
add_class_detector(TestClassDetector, t.Utf8String , TypeInfo.CONSTRUCTED, 0x0C)
add_class_detector(TestClassDetector, t.RelativeOid, TypeInfo.PRIMITIVE, 0x0D)
add_class_detector(TestClassDetector, t.Sequence, TypeInfo.CONSTRUCTED, 0x10, 'SEQUENCE and SEQUENCE OF')
add_class_detector(TestClassDetector, t.Set, TypeInfo.CONSTRUCTED, 0x11, 'SET and SET OF')
add_class_detector(TestClassDetector, t.NumericString, TypeInfo.PRIMITIVE, 0x12)
add_class_detector(TestClassDetector, t.NumericString, TypeInfo.CONSTRUCTED, 0x12)
add_class_detector(TestClassDetector, t.PrintableString , TypeInfo.PRIMITIVE, 0x13)
add_class_detector(TestClassDetector, t.PrintableString , TypeInfo.CONSTRUCTED, 0x13)
add_class_detector(TestClassDetector, t.T61String , TypeInfo.PRIMITIVE, 0x14)
add_class_detector(TestClassDetector, t.T61String , TypeInfo.CONSTRUCTED, 0x14)
add_class_detector(TestClassDetector, t.VideotexString , TypeInfo.PRIMITIVE, 0x15)
add_class_detector(TestClassDetector, t.VideotexString , TypeInfo.CONSTRUCTED, 0x15)
add_class_detector(TestClassDetector, t.IA5String , TypeInfo.PRIMITIVE, 0x16)
add_class_detector(TestClassDetector, t.IA5String , TypeInfo.CONSTRUCTED, 0x16)
add_class_detector(TestClassDetector, t.UtcTime , TypeInfo.PRIMITIVE, 0x17)
add_class_detector(TestClassDetector, t.UtcTime , TypeInfo.CONSTRUCTED, 0x17)
add_class_detector(TestClassDetector, t.GeneralizedTime , TypeInfo.PRIMITIVE, 0x18)
add_class_detector(TestClassDetector, t.GeneralizedTime , TypeInfo.CONSTRUCTED, 0x18)
add_class_detector(TestClassDetector, t.GraphicString , TypeInfo.PRIMITIVE, 0x19)
add_class_detector(TestClassDetector, t.GraphicString , TypeInfo.CONSTRUCTED, 0x19)
add_class_detector(TestClassDetector, t.VisibleString , TypeInfo.PRIMITIVE, 0x1a)
add_class_detector(TestClassDetector, t.VisibleString , TypeInfo.CONSTRUCTED, 0x1a)
add_class_detector(TestClassDetector, t.GeneralString , TypeInfo.PRIMITIVE, 0x1B)
add_class_detector(TestClassDetector, t.GeneralString , TypeInfo.CONSTRUCTED, 0x1b)
add_class_detector(TestClassDetector, t.UniversalString , TypeInfo.PRIMITIVE, 0x1c)
add_class_detector(TestClassDetector, t.UniversalString , TypeInfo.CONSTRUCTED, 0x1c)
add_class_detector(TestClassDetector, t.CharacterString , TypeInfo.PRIMITIVE, 0x1d)
add_class_detector(TestClassDetector, t.CharacterString , TypeInfo.CONSTRUCTED, 0x1d)
add_class_detector(TestClassDetector, t.BmpString , TypeInfo.PRIMITIVE, 0x1e)
add_class_detector(TestClassDetector, t.BmpString , TypeInfo.CONSTRUCTED, 0x1e)
