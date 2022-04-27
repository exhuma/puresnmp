"""
Exceptions for the puresnmp package.

Most exceptions in this module are based on :rfc:`3416`
"""

from typing import Any, List

from x690.types import ObjectIdentifier

from puresnmp.const import MAX_VARBINDS


class SnmpError(Exception):
    """
    Generic exception originating from the puresnmp package. Every SNMP related
    error inherits from this class.
    """

    # pylint: disable=too-few-public-methods


class ErrorResponse(SnmpError):
    """
    A superclass used when the SNMP agent responded with additional error
    information.
    """

    #: Default message to report for this error (if not overridden)
    DEFAULT_MESSAGE: str = "unknown error"

    #: The "error-status" value
    IDENTIFIER: int = 0

    #: the raw (int) value of the error-status as returned by the SNMP agent.
    error_status: int

    #: the OID identified in the error message which caused the error.
    offending_oid: ObjectIdentifier

    @staticmethod
    def construct(
        error_status: int, offending_oid: ObjectIdentifier, message: str = ""
    ) -> "ErrorResponse":
        """
        Creates a new instance of an ErrorResponse class, using the proper
        subclass for the given *error_status* value. The message is optional,
        and if not specified, will use the default message for the given class.
        """
        classes = {
            cls.IDENTIFIER: cls for cls in ErrorResponse.__subclasses__()
        }
        if error_status in classes:
            cls = classes[error_status]
            return cls(offending_oid, message)
        return ErrorResponse(offending_oid, message, error_status=error_status)

    def __init__(
        self,
        offending_oid: ObjectIdentifier,
        message: str = "",
        error_status: int = 0,
    ) -> None:
        error_status = error_status or self.IDENTIFIER
        super().__init__(
            "%s (status-code: %r) on OID %s"
            % (
                message or self.DEFAULT_MESSAGE,
                error_status,
                offending_oid or "unknown",
            )
        )
        self.error_status = error_status
        self.offending_oid = offending_oid


class TooBig(ErrorResponse):
    """
    This error is returned whenever the size of the generatred response exceeds
    a size-limit defined by the queried device.
    """

    DEFAULT_MESSAGE = "SNMP response was too big!"
    IDENTIFIER = 1


class NoSuchOID(ErrorResponse):
    """
    This error is returned in any of the following cases:

    * the targeted OID does not support "snmp-set" operations
    * the targeted OID does not exist.
    * the targeted OID is an SMI aggregate type.
    * the targeted OID does not precede a known name in the MIB view.
    """

    DEFAULT_MESSAGE = "No such name/oid"
    IDENTIFIER = 2


class BadValue(ErrorResponse):
    """
    This error is returned whenever a variable is set using an incompatible
    type.
    """

    DEFAULT_MESSAGE = "Bad value"
    IDENTIFIER = 3


class ReadOnly(ErrorResponse):
    """
    This error is returned whenever a variable is set which is not writable.
    """

    DEFAULT_MESSAGE = "Value is read-only!"
    IDENTIFIER = 4


class GenErr(ErrorResponse):
    """
    This error is returned for any error which is not covered in the previous
    error classes.
    """

    DEFAULT_MESSAGE = "General Error (genErr)"
    IDENTIFIER = 5


class NoAccess(ErrorResponse):
    """
    This error is returned whenever .
    """

    DEFAULT_MESSAGE = "No Access!"
    IDENTIFIER = 6


class WrongType(ErrorResponse):
    IDENTIFIER = 7


class WrongLength(ErrorResponse):
    IDENTIFIER = 8


class WrongEncoding(ErrorResponse):
    IDENTIFIER = 9


class WrongValue(ErrorResponse):
    IDENTIFIER = 10


class NoCreation(ErrorResponse):
    IDENTIFIER = 11


class InconsistentValue(ErrorResponse):
    IDENTIFIER = 12


class ResourceUnavailable(ErrorResponse):
    IDENTIFIER = 13


class CommitFailed(ErrorResponse):
    IDENTIFIER = 14


class UndoFailed(ErrorResponse):
    IDENTIFIER = 15


class AuthorizationError(ErrorResponse):
    IDENTIFIER = 16


class NotWritable(ErrorResponse):
    IDENTIFIER = 17


class InconsistentName(ErrorResponse):
    IDENTIFIER = 18


class EmptyMessage(SnmpError):
    """
    Raised when trying to decode an SNMP-Message with no content.
    """


class TooManyVarbinds(SnmpError):
    """
    Exception which is raised when the number of VarBinds exceeds the limit
    defined in :rfc:`3416`.
    """

    def __init__(self, num_oids):
        # type: (int) -> None
        super().__init__(
            "Too many VarBinds (%d) in one request!"
            " RFC3416 limits requests to %d!" % (num_oids, MAX_VARBINDS)
        )
        self.num_oids = num_oids


class Timeout(SnmpError):
    """
    Wrapper for network timeouts.

    This wraps both "socket.timeout" and "asyncio.TimeoutError"
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class FaultySNMPImplementation(SnmpError):
    """
    Exception which indicates an unexpected response from an SNMP agent.
    """


class NotInTimeWindow(SnmpError):
    """
    This exception is raised when a message is outside the time window

    .. seealso::
        `RFC-3414 - Section 3.2 - Processing an Incoming SNMP Message <https://tools.ietf.org/html/rfc3414#section-3.2>`_
            Reference description on how to handle incoming messages.
    """

    def __init__(self, oid: str, value: int, reporting: str) -> None:
        super().__init__()
        self.oid = oid
        self.value = value
        self.reporting = reporting


class InvalidResponseId(SnmpError):
    """
    Exception which is raised when a response is received that did not
    correspond to the request-id
    """


class MissingPlugin(SnmpError):
    """
    Raised when a pluggable module could not be found

    :param ns: The plugin namespace
    :param needle: The identifier that was looked up
    :param haystack: The known identifiers
    """

    def __init__(self, ns: str, needle: Any, haystack: List[Any]) -> None:
        msg = (
            f"Namespace {ns!r} did not contain a plugin "
            f"with identifier {needle!r}. "
            f"Known identifiers: {sorted(haystack)!r}. "
            "See the 'puresnmp' documentation on plugins."
        )
        super().__init__(msg)
        self.ns = ns
        self.needle = repr(needle)
        self.haystack = haystack


class UnknownMessageProcessingModel(MissingPlugin):
    """
    Raised if a message was not formatted according to any known model
    """


class UnknownSecurityModel(MissingPlugin):
    """
    This exception is raised when something goes wrong with a security model
    """


class UnknownAuthModel(MissingPlugin):
    """
    Exception which is raised when working with an unsupported/unknown
    authentication
    """


class UnknownPrivacyModel(MissingPlugin):
    """
    Exception which is raised when the security model in use is unknown.
    """
