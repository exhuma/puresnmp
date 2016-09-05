"""
SMI Types / Structure types which are not defined in ASN.1
"""

from .x690.types import Integer
from .x690.util import TypeInfo


class IpAddress(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x00


class Counter(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x01


class Gauge(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x02


class TimeTicks(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x03


class Opaque(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x04


class NsapAddress(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x05
