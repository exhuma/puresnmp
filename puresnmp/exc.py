"""
Exceptions for the puresnmp package.
"""
# pylint: disable=too-few-public-methods

import socket


class SnmpError(Exception):
    """
    Generic exception originating from the puresnmp package. Every SNMP related
    error inherits from this class.
    """
    pass


class Timeout(socket.timeout):
    """
    Wrapper for network timeouts.
    """
    # TODO: is this really needed? Why not bubble up socket.timeout?
    pass
