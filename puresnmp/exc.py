"""
Exceptions for the puresnmp package.
"""
# pylint: disable=too-few-public-methods

import socket
from puresnmp.const import MAX_VARBINDS


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


class TooManyVarbinds(SnmpError):

    def __init__(self, num_oids):
        super().__init__('Too many VarBinds (%d) in one request! RFC3416 '
                         'limits requests to %d!' % (
                             num_oids, MAX_VARBINDS))
        self.num_oids = num_oids


class Timeout(socket.timeout):
    """
    Wrapper for network timeouts.
    """
    # TODO: is this really needed? Why not bubble up socket.timeout?
    pass
