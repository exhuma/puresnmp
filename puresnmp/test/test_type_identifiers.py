from ..x690 import types as t
from ..x690.types import TypeInfo

from . import ByteTester


def make_identifier_test(octet, expected_class, expected_pc, expected_value):
    def fun(self):
        result = TypeInfo.from_bytes(octet)
        expected = TypeInfo(expected_class, expected_pc, expected_value)
        self.assertEqual(result, expected)
    return fun


def add_class_detector(cls, expected_class, tag):
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


add_class_detector(TestClassDetector, t.EOC, 0x00)
add_class_detector(TestClassDetector, t.Boolean, 0x01)
add_class_detector(TestClassDetector, t.Integer, 0x02)
add_class_detector(TestClassDetector, t.BitString, 0x03)
add_class_detector(TestClassDetector, t.OctetString, 0x04)
add_class_detector(TestClassDetector, t.Null, 0x05)
add_class_detector(TestClassDetector, t.ObjectIdentifier, 0x06)
add_class_detector(TestClassDetector, t.ObjectDescriptor, 0x07)
add_class_detector(TestClassDetector, t.External, 0x08)
add_class_detector(TestClassDetector, t.Real, 0x09)
add_class_detector(TestClassDetector, t.Enumerated, 0x0A)
add_class_detector(TestClassDetector, t.EmbeddedPdv, 0x0B)
add_class_detector(TestClassDetector, t.Utf8String, 0x0C)
add_class_detector(TestClassDetector, t.RelativeOid, 0x0D)
add_class_detector(TestClassDetector, t.Sequence, 0x10)
add_class_detector(TestClassDetector, t.Set, 0x11)
add_class_detector(TestClassDetector, t.NumericString, 0x12)
add_class_detector(TestClassDetector, t.PrintableString, 0x13)
add_class_detector(TestClassDetector, t.T61String, 0x14)
add_class_detector(TestClassDetector, t.VideotexString, 0x15)
add_class_detector(TestClassDetector, t.IA5String, 0x16)
add_class_detector(TestClassDetector, t.UtcTime, 0x17)
add_class_detector(TestClassDetector, t.GeneralizedTime, 0x18)
add_class_detector(TestClassDetector, t.GraphicString, 0x19)
add_class_detector(TestClassDetector, t.VisibleString, 0x1a)
add_class_detector(TestClassDetector, t.GeneralString, 0x1b)
add_class_detector(TestClassDetector, t.UniversalString, 0x1c)
add_class_detector(TestClassDetector, t.CharacterString, 0x1d)
add_class_detector(TestClassDetector, t.BmpString, 0x1e)
