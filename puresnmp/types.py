"""
SMI Types / Structure types which are not defined in the x690 protocol (see
also :py:mod:`x690`).

See `RFC 1155 section 3.2.3`_ for a description of the types and `RFC 3416`_
for the definition of the new types.

.. note::
    The IPv6 type is not defined in the default RFCs and needs to be
    post-processed.

.. _RFC 1155 section 3.2.3: https://tools.ietf.org/html/rfc1155#section-3.2.3
.. _RFC 3416: https://tools.ietf.org/html/rfc3416
"""
# TODO: Implement IPv6 via https://tools.ietf.org/html/rfc2465
# pylint: disable=too-few-public-methods

from datetime import timedelta
from ipaddress import IPv4Address, ip_address
from typing import Optional, Union

from x690.types import (
    _SENTINEL_UNINITIALISED,
    UNINITIALISED,
    Integer,
    OctetString,
)
from x690.types import X690Type as Type
from x690.util import TypeClass


class IpAddress(Type[IPv4Address]):
    """
    SNMP Type for IPv4 Addresses
    """

    NATURE = OctetString.NATURE
    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x00

    def encode_raw(self) -> bytes:
        """
        Converts ip-address instance into raw bytes

        >>> IpAddress(ip_address('192.0.2.1')).encode_raw()
        b'\\xc0\\x00\\x02\\x01'
        """
        numeric = int(self.value)
        return numeric.to_bytes(4, "big")

    @staticmethod
    def decode_raw(data: bytes, slc: slice = slice(None)) -> IPv4Address:
        """
        Converts raw-bytes to an ip-address instance

        >>> IpAddress.decode_raw(b"\\xc0\\x00\\x02\\x01")
        IPv4Address('192.0.2.1')
        """
        value = ip_address(int.from_bytes(data[slc], "big"))
        return value  # type: ignore

    def __eq__(self, other: object) -> bool:
        # TODO: no longer necessary in x690 > 0.5.0a4
        return isinstance(other, IpAddress) and self.value == other.value


class Counter(Integer):
    """
    SNMP type for counters.
    """

    SIGNED = False
    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x01

    def __init__(
        self, value: Union[int, _SENTINEL_UNINITIALISED] = UNINITIALISED
    ) -> None:
        if not isinstance(value, _SENTINEL_UNINITIALISED):
            value &= 0xFFFFFFFF if value >= 2**32 else value
            if value <= 0:
                value = 0
        super().__init__(value)


class Gauge(Integer):
    """
    SNMP type for gauges.
    """

    SIGNED = False
    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x02


class TimeTicks(Integer):
    """
    SNMP type for time ticks exposed as Python :py:class:`datetime.timedelta`
    """

    SIGNED = False
    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x03

    def __init__(
        self,
        value: Union[timedelta, int, _SENTINEL_UNINITIALISED] = UNINITIALISED,
    ) -> None:
        if isinstance(value, timedelta):
            value = int(value.total_seconds() * 100)
        super().__init__(value)

    def pythonize(self) -> Optional[timedelta]:  # type: ignore
        """
        Convert to Python type
        """
        if self.value is None:
            return None
        seconds = self.value / 100.0  # see rfc2578#section-7.1.8
        return timedelta(seconds=seconds)


class Opaque(OctetString):
    """
    The Opaque type is to be considered to carry "any" binary data.

    It is up to the application to know how to interpret this data and is
    passed through transparently by the SNMP protocol.
    """

    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x04


class NsapAddress(Integer):
    """
    Wrapped type for an NSAP Address
    """

    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x05


class Counter64(Integer):
    """
    As defined in RFC 2578
    """

    SIGNED = False
    TYPECLASS = TypeClass.APPLICATION
    TAG = 0x06

    def __init__(
        self, value: Union[int, _SENTINEL_UNINITIALISED] = UNINITIALISED
    ) -> None:
        if not isinstance(value, _SENTINEL_UNINITIALISED):
            value &= 0xFFFFFFFFFFFFFFFF if value >= 2**64 else value
            if value <= 0:
                value = 0
        super().__init__(value)


def _walk_subclasses(cls, indent=0):  # pragma: no cover
    # type: (type, int) -> None
    """
    Recursively walk over the :py:class:`Type` hierarchy and print out ReST
    formatted text on stdout.
    """
    if cls.__module__ == "__main__":
        modname = "puresnmp.types"
    else:
        modname = cls.__module__

    cname = ".".join([modname, cls.__qualname__])
    ref = ":py:class:`%s`" % cname

    print("\n", "   " * indent, "* ", ref)
    for subclass in sorted(
        cls.__subclasses__(), key=lambda x: x.__module__ + x.__name__
    ):
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

    print(".. _type_tree:\n")
    print("Type Tree")
    print("=========\n")
    _walk_subclasses(Type)
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys  # pylint: disable=ungrouped-imports

    sys.exit(main())
