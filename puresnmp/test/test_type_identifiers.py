# pylint: skip-file

from ..x690 import types as t
from ..x690.util import TypeInfo
from .. import types as apptype

from . import ByteTester


UNIVERSAL = TypeInfo.UNIVERSAL
APPLICATION = TypeInfo.APPLICATION
PRIMITIVE = TypeInfo.PRIMITIVE
PRIVATE = TypeInfo.PRIVATE
CONSTRUCTED = TypeInfo.CONSTRUCTED
CONTEXT = TypeInfo.CONTEXT


def make_identifier_test(octet, expected_class, expected_pc, expected_value):
    def fun(self):
        result = TypeInfo.from_bytes(octet)
        expected = TypeInfo(expected_class, expected_pc, expected_value)
        self.assertEqual(result, expected)
    return fun


def add_class_detector(cls, expected_class, typeclass, tag):
    def fun(inst):
        result = t.Registry.get(typeclass, tag)
        inst.assertEqual(result, expected_class)
    fun.__name__ = 'test_%s' % expected_class.__name__
    setattr(cls, 'test_%s' % expected_class.__name__, fun)


class TestBasics(ByteTester):

    test_identifier_univ_prim = make_identifier_test(
        0b00000010, UNIVERSAL, PRIMITIVE, 0b00010)

    test_identifier_univ_const = make_identifier_test(
        0b00100010, UNIVERSAL, CONSTRUCTED, 0b00010)

    test_identifier_app_prim = make_identifier_test(
        0b01000010, APPLICATION, PRIMITIVE, 0b00010)

    test_identifier_app_const = make_identifier_test(
        0b01100010, APPLICATION, CONSTRUCTED, 0b00010)

    test_identifier_ctx_prim = make_identifier_test(
        0b10000010, CONTEXT, PRIMITIVE, 0b00010)

    test_identifier_ctx_const = make_identifier_test(
        0b10100010, CONTEXT, CONSTRUCTED, 0b00010)

    test_identifier_prv_prim = make_identifier_test(
        0b11000010, PRIVATE, PRIMITIVE, 0b00010)

    test_identifier_prv_const = make_identifier_test(
        0b11100010, PRIVATE, CONSTRUCTED, 0b00010)

    def test_identifier_long(self):
        self.skipTest('This is not yet implemented. I have not understood the '
                      'spec to confidently write a test')  # TODO


class TestClassDetector(ByteTester):
    pass


# "Standard" x690 types
add_class_detector(TestClassDetector, t.EOC, UNIVERSAL, 0x00)
add_class_detector(TestClassDetector, t.Boolean, UNIVERSAL, 0x01)
add_class_detector(TestClassDetector, t.Integer, UNIVERSAL, 0x02)
add_class_detector(TestClassDetector, t.BitString, UNIVERSAL, 0x03)
add_class_detector(TestClassDetector, t.OctetString, UNIVERSAL, 0x04)
add_class_detector(TestClassDetector, t.Null, UNIVERSAL, 0x05)
add_class_detector(TestClassDetector, t.ObjectIdentifier, UNIVERSAL, 0x06)
add_class_detector(TestClassDetector, t.ObjectDescriptor, UNIVERSAL, 0x07)
add_class_detector(TestClassDetector, t.External, UNIVERSAL, 0x08)
add_class_detector(TestClassDetector, t.Real, UNIVERSAL, 0x09)
add_class_detector(TestClassDetector, t.Enumerated, UNIVERSAL, 0x0A)
add_class_detector(TestClassDetector, t.EmbeddedPdv, UNIVERSAL, 0x0B)
add_class_detector(TestClassDetector, t.Utf8String, UNIVERSAL, 0x0C)
add_class_detector(TestClassDetector, t.RelativeOid, UNIVERSAL, 0x0D)
add_class_detector(TestClassDetector, t.Sequence, UNIVERSAL, 0x10)
add_class_detector(TestClassDetector, t.Set, UNIVERSAL, 0x11)
add_class_detector(TestClassDetector, t.NumericString, UNIVERSAL, 0x12)
add_class_detector(TestClassDetector, t.PrintableString, UNIVERSAL, 0x13)
add_class_detector(TestClassDetector, t.T61String, UNIVERSAL, 0x14)
add_class_detector(TestClassDetector, t.VideotexString, UNIVERSAL, 0x15)
add_class_detector(TestClassDetector, t.IA5String, UNIVERSAL, 0x16)
add_class_detector(TestClassDetector, t.UtcTime, UNIVERSAL, 0x17)
add_class_detector(TestClassDetector, t.GeneralizedTime, UNIVERSAL, 0x18)
add_class_detector(TestClassDetector, t.GraphicString, UNIVERSAL, 0x19)
add_class_detector(TestClassDetector, t.VisibleString, UNIVERSAL, 0x1a)
add_class_detector(TestClassDetector, t.GeneralString, UNIVERSAL, 0x1b)
add_class_detector(TestClassDetector, t.UniversalString, UNIVERSAL, 0x1c)
add_class_detector(TestClassDetector, t.CharacterString, UNIVERSAL, 0x1d)
add_class_detector(TestClassDetector, t.BmpString, UNIVERSAL, 0x1e)


# Application (SNMP-specific) Types
add_class_detector(TestClassDetector, apptype.IpAddress, APPLICATION, 0x00)
add_class_detector(TestClassDetector, apptype.Counter, APPLICATION, 0x01)
add_class_detector(TestClassDetector, apptype.Gauge, APPLICATION, 0x02)
add_class_detector(TestClassDetector, apptype.TimeTicks, APPLICATION, 0x03)
add_class_detector(TestClassDetector, apptype.Opaque, APPLICATION, 0x04)
add_class_detector(TestClassDetector, apptype.NsapAddress, APPLICATION, 0x05)
add_class_detector(TestClassDetector, apptype.Counter64, APPLICATION, 0x06)
