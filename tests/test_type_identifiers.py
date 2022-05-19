# pylint: skip-file

from x690 import types as t
from x690.util import TypeClass, TypeInfo, TypeNature

from puresnmp import types as apptype

from . import ByteTester

UNIVERSAL = TypeClass.UNIVERSAL
APPLICATION = TypeClass.APPLICATION
PRIVATE = TypeClass.PRIVATE
CONTEXT = TypeClass.CONTEXT
PRIMITIVE = TypeNature.PRIMITIVE
CONSTRUCTED = TypeNature.CONSTRUCTED


def make_identifier_test(octet, expected_class, expected_pc, expected_value):
    def fun(self):
        result = TypeInfo.from_bytes(octet)
        expected = TypeInfo(expected_class, expected_pc, expected_value)
        self.assertEqual(result, expected)

    return fun


def add_class_detector(cls, expected_class, typeclass, tag, pc=PRIMITIVE):
    def fun(inst):
        result = t.X690Type.get(typeclass, tag, pc)
        inst.assertEqual(result, expected_class)

    fun.__name__ = "test_%s" % expected_class.__name__
    setattr(cls, "test_%s" % expected_class.__name__, fun)


class TestBasics(ByteTester):

    test_identifier_univ_prim = make_identifier_test(
        0b00000010, UNIVERSAL, PRIMITIVE, 0b00010
    )

    test_identifier_univ_const = make_identifier_test(
        0b00100010, UNIVERSAL, CONSTRUCTED, 0b00010
    )

    test_identifier_app_prim = make_identifier_test(
        0b01000010, APPLICATION, PRIMITIVE, 0b00010
    )

    test_identifier_app_const = make_identifier_test(
        0b01100010, APPLICATION, CONSTRUCTED, 0b00010
    )

    test_identifier_ctx_prim = make_identifier_test(
        0b10000010, CONTEXT, PRIMITIVE, 0b00010
    )

    test_identifier_ctx_const = make_identifier_test(
        0b10100010, CONTEXT, CONSTRUCTED, 0b00010
    )

    test_identifier_prv_prim = make_identifier_test(
        0b11000010, PRIVATE, PRIMITIVE, 0b00010
    )

    test_identifier_prv_const = make_identifier_test(
        0b11100010, PRIVATE, CONSTRUCTED, 0b00010
    )


class TestClassDetector(ByteTester):
    pass


# Application (SNMP-specific) Types
add_class_detector(TestClassDetector, apptype.IpAddress, APPLICATION, 0x00)
add_class_detector(TestClassDetector, apptype.Counter, APPLICATION, 0x01)
add_class_detector(TestClassDetector, apptype.Gauge, APPLICATION, 0x02)
add_class_detector(TestClassDetector, apptype.TimeTicks, APPLICATION, 0x03)
add_class_detector(TestClassDetector, apptype.Opaque, APPLICATION, 0x04)
add_class_detector(TestClassDetector, apptype.NsapAddress, APPLICATION, 0x05)
add_class_detector(TestClassDetector, apptype.Counter64, APPLICATION, 0x06)
