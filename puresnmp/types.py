"""
SMI Types / Structure types which are not defined in :term:`X.690`.

See `RFC 1155 section 3.2.3`_ for a description of the types.

.. _RFC 1155 section 3.2.3: https://tools.ietf.org/html/rfc1155#section-3.2.3
"""

# pylint: disable=missing-docstring

from datetime import timedelta

from .x690.types import Integer, OctetString
from .x690.util import TypeInfo


class IpAddress(OctetString):
    """
    SNMP Type for IP Addresses
    """
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x00


class Counter(Integer):
    """
    SNMP type for counters.
    """
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x01


class Gauge(Integer):
    """
    SNMP type for gauges.
    """
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x02


class TimeTicks(Integer):
    """
    SNMP type for time ticks.
    """
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x03

    def __init__(self, value):
        if isinstance(value, timedelta):
            value = int(value.total_seconds() * 100)
        super().__init__(value)

    def pythonize(self):
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
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x06


def _walk_subclasses(cls, indent=0):
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


def main():
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


if __name__ == '__main__':
    import sys
    sys.exit(main())
