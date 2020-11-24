"""
SMI Types / Structure types which are not defined in :term:`X.690`.

See `RFC 1155 section 3.2.3`_ for a description of the types and `RFC 3416`_
for the definition of the new types.

.. note::
    The IPv6 Type is not yet implemented and will be returned as OctetString!

.. _RFC 1155 section 3.2.3: https://tools.ietf.org/html/rfc1155#section-3.2.3
.. _RFC 3416: https://tools.ietf.org/html/rfc3416
"""
# TODO: Implement IPv6 via https://tools.ietf.org/html/rfc2465

import sys
from datetime import timedelta
from ipaddress import IPv4Address
from struct import pack
from typing import TYPE_CHECKING, Union

from .x690.types import Integer, OctetString
from .x690.util import TypeInfo

if TYPE_CHECKING:
    from typing import Optional


class IpAddress(OctetString):
    """
    SNMP Type for IPv4 Addresses
    """
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x00

    def __init__(self, value):
        # type: (bytes) -> None
        if isinstance(value, IPv4Address):
            remainder = int(value)
            octet_4, remainder = remainder & 0xff, remainder >> 8
            octet_3, remainder = remainder & 0xff, remainder >> 8
            octet_2, remainder = remainder & 0xff, remainder >> 8
            octet_1, remainder = remainder & 0xff, remainder >> 8
            value = pack('BBBB', octet_1, octet_2, octet_3, octet_4)
        super(IpAddress, self).__init__(value)

    def pythonize(self):
        # type: () -> Optional[bytes]
        return self.value

        # TODO The following code breaks backwards compatbility and should be
        # released in the next mator verion

        # TODO v2.0.0 intvalue = 0
        # TODO v2.0.0 for i, octet in enumerate(reversed(self.value)):
        # TODO v2.0.0     if sys.version_info < (3, 0):
        # TODO v2.0.0         # Python 2 assumes has str === bytes so we need to cast
        # TODO v2.0.0         octet = ord(octet)
        # TODO v2.0.0     intvalue |= octet << (8*i)
        # TODO v2.0.0 return ip_address(intvalue)


class Counter(Integer):
    """
    SNMP type for counters.
    """
    SIGNED = False
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x01

    def __init__(self, value):
        # type: (int) -> None
        value &= 0xFFFFFFFF if value >= 2 ** 32 else value
        if value <= 0:
            value = 0
        super(Counter, self).__init__(value)


class Gauge(Integer):
    """
    SNMP type for gauges.
    """
    SIGNED = False
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x02


class TimeTicks(Integer):
    """
    SNMP type for time ticks.
    """
    SIGNED = False
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x03

    def __init__(self, value):
        # type: (Union[timedelta, int]) -> None
        if isinstance(value, timedelta):
            value_int = int(value.total_seconds() * 100)
        else:
            value_int = value
        super(TimeTicks, self).__init__(value_int)

    def pythonize(self):
        # type: () -> Optional[timedelta]
        if self.value is None:
            return None
        seconds = self.value / 100.0  # see rfc2578#section-7.1.8
        return timedelta(seconds=seconds)


class Opaque(OctetString):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x04


class NsapAddress(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x05


class Counter64(Integer):
    """
    As defined in RFC 2578
    """
    SIGNED = False
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x06

    def __init__(self, value):
        # type: (int) -> None
        value &= 0xFFFFFFFFFFFFFFFF if value >= 2 ** 64 else value
        if value <= 0:
            value = 0
        super(Counter64, self).__init__(value)


def _walk_subclasses(cls, indent=0):  # pragma: no cover
    # type: (type, int) -> None
    '''
    Recursively walk over the :py:class:`Type` hierarchy and print out ReST
    formatted text on stdout.
    '''
    if cls.__module__ == '__main__':
        modname = 'puresnmp.types'
    else:
        modname = cls.__module__

    cname = '.'.join([modname, cls.__qualname__])
    ref = ':py:class:`%s`' % cname

    print('\n', '   ' * indent, '* ', ref)
    for subclass in sorted(cls.__subclasses__(),
                           key=lambda x: x.__module__ + x.__name__):
        _walk_subclasses(subclass, indent + 1)


def main():  # pragma: no cover
    # type: () -> int
    """
    Entrypoint for::

        python -m puresnmp.types

    This will output a RST formatted document containing the available types.
    This function was written to generate a documentation page with the
    available types.
    """
    from .x690.types import Type
    print('.. _type_tree:\n')
    print('Type Tree')
    print('=========\n')
    _walk_subclasses(Type)
    return 0


if __name__ == '__main__':  # pragma: no cover
    import sys
    sys.exit(main())
