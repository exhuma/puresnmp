"""
This file contains various values used to avoid magic numbers and strings in
the application.
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

#: Maximum number of usable varbinds as defined in RFC 3416
MAX_VARBINDS = 2147483647

#: A magic value used to detect strict error-handling
ERRORS_STRICT = 'strict'

#: A magic value used to detect lenient error-handling
ERRORS_WARN = 'warn'

#: TCP timeout which is used if not manually overridden
DEFAULT_TIMEOUT = 6
