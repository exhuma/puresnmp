"""
Exceptions for the puresnmp package.
"""
from __future__ import unicode_literals

import socket
from typing import Optional
from puresnmp.const import MAX_VARBINDS

from .x690.types import ObjectIdentifier

# pylint: disable=too-few-public-methods


class SnmpError(Exception):
    """
    Generic exception originating from the puresnmp package. Every SNMP related
    error inherits from this class.
    """


class ErrorResponse(SnmpError):
    """
    A superclass used when the SNMP agent responded with additional error
    information.

    Instances of ``ErrorResponse`` have two attributes concerning the error:

    * ``error_status`` the raw (int) value of the error-status as returned by
      the SNMP agent.
    * ``offending_oid`` the OID identified in the error message which caused
      the error.
    """

    DEFAULT_MESSAGE = 'unknown error'

    @staticmethod
    def construct(error_status, offending_oid, message=''):
        # type: (int, Optional[ObjectIdentifier], str) -> ErrorResponse
        """
        Creates a new instance of an ErrorResponse class, using the proper
        subclass for the given *error_status* value. The message is optional,
        and if not specified, will use the default message for the given class.
        """
        if error_status == 1:
            return TooBig(offending_oid, message)
        if error_status == 2:
            return NoSuchOID(offending_oid, message)
        if error_status == 3:
            return BadValue(offending_oid, message)
        if error_status == 4:
            return ReadOnly(offending_oid, message)
        if error_status == 5:
            return GenErr(offending_oid, message)
        if error_status == 6:
            return NoAccess(offending_oid, message)
        return ErrorResponse(error_status, offending_oid, message)

    def __init__(self, error_status, offending_oid, message=''):
        # type: (int, Optional[ObjectIdentifier], str) -> None
        super(ErrorResponse, self).__init__(
            '%s (status-code: %r) on OID %s' % (
                message or self.DEFAULT_MESSAGE, error_status, offending_oid if offending_oid != None else "unknown"))
        self.error_status = error_status
        self.offending_oid = offending_oid


class TooBig(ErrorResponse):
    """
    This error is returned whenever the size of the generatred response exceeds
    a size-limit defined by the queried device.
    """
    DEFAULT_MESSAGE = 'SNMP response was too big!'
    def __init__(self, offending_oid, message=''):
        # type: (Optional[ObjectIdentifier], str) -> None
        super(TooBig, self).__init__(1, offending_oid)


class NoSuchOID(ErrorResponse):
    """
    This error is returned in any of the following cases:

    * the targeted OID does not support "snmp-set" operations
    * the targeted OID does not exist.
    * the targeted OID is an SMI aggregate type.
    * the targeted OID does not precede a known name in the MIB view.
    """

    DEFAULT_MESSAGE = 'No such name/oid'

    def __init__(self, offending_oid, message=''):
        # type: (Optional[ObjectIdentifier], str) -> None
        super(NoSuchOID, self).__init__(2, offending_oid, message)


class BadValue(ErrorResponse):
    """
    This error is returned whenever a variable is set using an incompatible
    type.
    """

    DEFAULT_MESSAGE = 'Bad value'

    def __init__(self, offending_oid, message=''):
        # type: (Optional[ObjectIdentifier], str) -> None
        super(BadValue, self).__init__(3, offending_oid, message)


class ReadOnly(ErrorResponse):
    """
    This error is returned whenever a variable is set which is not writable.
    """

    DEFAULT_MESSAGE = 'Value is read-only!'

    def __init__(self, offending_oid, message=''):
        # type: (Optional[ObjectIdentifier], str) -> None
        super(ReadOnly, self).__init__(4, offending_oid, message)


class NoAccess(ErrorResponse):
    """
    This error is returned whenever .
    """

    DEFAULT_MESSAGE = 'No Access!'

    def __init__(self, offending_oid, message=''):
        # type: (Optional[ObjectIdentifier], str) -> None
        super(NoAccess, self).__init__(6, offending_oid, message)


class GenErr(ErrorResponse):
    """
    This error is returned for any error which is not covered in the previous
    error classes.
    """

    DEFAULT_MESSAGE = 'General Error (genErr)'

    def __init__(self, offending_oid, message=''):
        # type: (Optional[ObjectIdentifier], str) -> None
        super(GenErr, self).__init__(5, offending_oid, message)


class EmptyMessage(SnmpError):
    """
    Raised when trying to decode an SNMP-Message with no content.
    """


class TooManyVarbinds(SnmpError):
    '''
    Exception which is raised when the number of VarBinds exceeds the limit
    defined in RFC3416.
    device.
    '''

    def __init__(self, num_oids):
        # type: (int) -> None
        super(TooManyVarbinds, self).__init__(
            'Too many VarBinds (%d) in one request!'
            ' RFC3416 limits requests to %d!' % (
                num_oids, MAX_VARBINDS))
        self.num_oids = num_oids


class Timeout(socket.timeout):
    """
    Wrapper for network timeouts.

    This wraps both "socket.timeout" and "asyncio.TimeoutError"
    """

    def __init__(self, message):
        # type: (str) -> None
        super(Timeout, self).__init__(message)
        self.message = message


class FaultySNMPImplementation(SnmpError):
    '''
    Exception which indicates an unexpected response from an SNMP agent.
    '''
