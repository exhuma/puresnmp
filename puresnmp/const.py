"""
This file contains various values used to avoid magic numbers and strings in the
application.
"""
# pylint: disable=too-few-public-methods


class Version:
    """
    The SNMP Version identifier. This is used in the SNMP :term:`PDU`.
    """

    V2C = 0x01
    V1 = 0x00


class Length:
    """
    A simple "namespace" to avoid magic values for indefinite lengths.
    """

    INDEFINITE = "indefinite"


MAX_VARBINDS = 2147483647  # Defined in RFC 3416
