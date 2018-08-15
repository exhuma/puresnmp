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


class EmptyMessage(SnmpError):
    """
    Raised when trying to decode an SNMP-Message with no content.
    """


class NoSuchOID(SnmpError):
    """
    Exception which is raised when accessing an OID which does not exist on the
    device.
    """


class TooManyVarbinds(SnmpError):
    '''
    Exception which is raised when the number of VarBinds exceeds the limit
    defined in RFC3416.
    device.
    '''

    def __init__(self, num_oids):
        super(TooManyVarbinds, self).__init__(
            'Too many VarBinds (%d) in one request!'
            ' RFC3416 limits requests to %d!' % (
                num_oids, MAX_VARBINDS))
        self.num_oids = num_oids


class Timeout(socket.timeout):
    """
    Wrapper for network timeouts.
    """
    # TODO: is this really needed? Why not bubble up socket.timeout?


class FaultySNMPImplementation(SnmpError):
    '''
    Exception which indicates an unexpected response from an SNMP agent.
    '''
