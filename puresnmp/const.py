"""
This file contains various values used to avoid magic numbers and strings in
the application.
"""
from enum import Enum


class Version(int, Enum):
    """
    The SNMP Version identifier. This is used in the SNMP
    :py:class:`puresnmp.pdu.PDU`.

    This avoids ambiguity with "v2" having the IDs 1 and 2, while v1 has the
    ID 0

    .. seealso::

        `Message Processing Models <https://www.iana.org/assignments/snmp-number-spaces/snmp-number-spaces.xml#snmp-number-spaces-2>`_
            IANA registry of version numbers
    """

    V1 = 0
    V2C = 1
    V2X = 2
    V3 = 3


class Length(str, Enum):
    """
    A simple "namespace" to avoid magic values for indefinite lengths.
    """

    INDEFINITE = "indefinite"


#: Maximum number of usable varbinds as defined in :rfc:`3416`
MAX_VARBINDS = 2147483647

#: A magic value used to detect strict error-handling
ERRORS_STRICT = "strict"

#: A magic value used to detect lenient error-handling
ERRORS_WARN = "warn"

#: TCP timeout which is used if not manually overridden
DEFAULT_TIMEOUT = 6
