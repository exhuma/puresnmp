"""
SMI Types
"""

from .x690.util import TypeInfo
from .x690.types import Integer


class TimeTicks(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x03


class Gauge(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x02
