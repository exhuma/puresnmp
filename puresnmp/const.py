"""
This file contains various values used in the SNMP standard.
"""


class Version:
    """
    Class to "hide" magic values.
    """

    V2C = 0x01
    V1 = 0x00


class Length:
    """
    A simple "namespace" to avoid magic values for indefinite lengths.
    """
    # pylint: disable=too-few-public-methods

    INDEFINITE = "indefinite"
