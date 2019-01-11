"""
This module contains exceptions for the x.690 protocol
"""


class X690Error(Exception):
    """
    Top-Level exception for everything related to the X690 protocol
    """


class InvalidValueLength(ValueError):
    """
    This error is raised when a value when the length information in the header
    of a "TLV" value does not match the actual value length.

    A likely scenario for this to happen is for example if an IO-operation
    ended prematurely. For example, if the UDP buffer size is too small and the
    remote device returns a packet larger than the buffer.
    """
