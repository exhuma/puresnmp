"""
This file contains various values used to avoid magic numbers and strings in
the application.
"""
from enum import Enum


class Version(int, Enum):
    """
    The SNMP Version identifier. This is used in the SNMP :term:`PDU`.
    """

    V2C = 0x01
    V1 = 0x00


class Length(str, Enum):
    """
    A simple "namespace" to avoid magic values for indefinite lengths.
    """

    INDEFINITE = "indefinite"


#: Maximum number of usable varbinds as defined in RFC 3416
MAX_VARBINDS = 2147483647

#: A magic value used to detect strict error-handling
ERRORS_STRICT = "strict"

#: A magic value used to detect lenient error-handling
ERRORS_WARN = "warn"

#: TCP timeout which is used if not manually overridden
DEFAULT_TIMEOUT = 6


class TransportDomain(int, Enum):
    """
    See :rfc:`3419`
    """

    UNKNOWN = 0
    UDPIPV4 = 1
    UDPIPV6 = 2
    UDPIPV4Z = 3
    UDPIPV6Z = 4
    TCPIPV4 = 5
    TCPIPV6 = 6
    TCPIPV4Z = 7
    TCPIPV6Z = 8
    SCTPIPV4 = 9
    SCTPIPV6 = 10
    SCTPIPV4Z = 11
    SCTPIPV6Z = 12
    LOCAL = 13
    UDPDNS = 14
    TCPDNS = 15
    SCTPDNS = 16
