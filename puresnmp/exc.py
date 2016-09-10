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


class EmptyMessage(SnmpError):
    """
    Raised when trying to decode an SNMP-Message with no content.
    """
    pass


class NoSuchOID(SnmpError):
    """
    Exception which is raised when accessing an OID which does not exist on the
    device.
    """
    pass


class Timeout(socket.timeout):
    """
    Wrapper for network timeouts.
    """
    # TODO: is this really needed? Why not bubble up socket.timeout?
    pass
