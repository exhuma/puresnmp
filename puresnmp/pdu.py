"""
Model for SNMP PDUs (Request/Response messages).

PDUs all have a common structure, which is handled in the
:py:class:`~.PDU` class. The different (basic) PDU types only differ in
their type identifier header (f.ex. ``b'\\xa0'`` for a
:py:class:`~.GetRequest`).
"""

# TODO: Add a method to wrap a message in a full packet (including SNMP version
#       and community). This can then replace some duplicated code in
#       "puresnmp.get", "puresnmp.walk" & co.

from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Tuple, cast

from x690 import decode
from x690.types import Integer, Null, ObjectIdentifier, Sequence, Type
from x690.util import TypeClass, TypeInfo, TypeNature, encode_length

from .const import MAX_VARBINDS
from .exc import (
    EmptyMessage,
    ErrorResponse,
    NoSuchOID,
    SnmpError,
    TooManyVarbinds,
)
from .snmp import VarBind
from .typevars import SocketInfo


@dataclass
class PDUContent:
    request_id: int
    varbinds: List[VarBind]
    error_status: int = 0
    error_index: int = 0


class PDU(Type[PDUContent]):
    """
    The superclass for SNMP Messages (GET, SET, GETNEXT, ...)
    """

    TYPECLASS = TypeClass.CONTEXT
    TAG = 0

    @classmethod
    def decode_raw(cls, data: bytes, slc: slice = slice(None)) -> PDUContent:
        """
        This method takes a :py:class:`bytes` object and converts it to
        an application object. This is callable from each subclass of
        :py:class:`~.PDU`.
        """
        # TODO (advanced): recent tests revealed that this is *not symmetric*
        # with __bytes__ of this class. This should be ensured!
        if not data:
            raise EmptyMessage("No data to decode!")
        request_id, next_start = decode(data, slc.start or 0)
        error_status, next_start = decode(data, next_start)
        error_index, next_start = decode(data, next_start)

        if error_status.value:
            error_detail, next_start = cast(
                Tuple[Iterable[Tuple[ObjectIdentifier, int]], bytes],
                decode(data, next_start),
            )
            if not isinstance(error_detail, Sequence):
                raise TypeError(
                    "error-detail should be a sequence but got %r"
                    % type(error_detail)
                )
            varbinds = [VarBind(*raw_varbind) for raw_varbind in error_detail]
            if error_index.value != 0:
                offending_oid = varbinds[error_index.value - 1].oid
            else:
                # Offending OID is unknown
                offending_oid = None
            exception = ErrorResponse.construct(
                error_status.value, offending_oid
            )
            raise exception

        values, next_start = decode(data, next_start)

        if not isinstance(values, Sequence):
            raise TypeError(
                "PDUs can only be decoded from sequences but got "
                "%r instead" % type(values)
            )

        varbinds = []
        for oid, value in values:
            # NOTE: this uses the "is" check to make 100% sure we check against
            # the sentinel object defined in this module!
            if isinstance(value, EndOfMibView):
                varbinds.append(VarBind(oid, value))
                break
            varbinds.append(VarBind(oid, value))

        return PDUContent(
            request_id.value, varbinds, error_status.value, error_index.value
        )

    def encode_raw(self) -> bytes:

        wrapped_varbinds = [
            Sequence([vb.oid, vb.value]) for vb in self.value.varbinds
        ]
        data: List[Type[Any]] = [
            Integer(self.value.request_id),
            Integer(self.value.error_status),
            Integer(self.value.error_index),
            Sequence(wrapped_varbinds),
        ]
        payload = b"".join([bytes(chunk) for chunk in data])
        return payload

    def __repr__(self) -> str:
        return "%s(%r, %r)" % (
            self.__class__.__name__,
            self.value.request_id,
            self.value.varbinds,
        )

    def __eq__(self, other: Any) -> bool:
        # pylint: disable=unidiomatic-typecheck
        return type(other) == type(self) and self.value == other.value

    def pretty(self, depth: int = 0) -> str:  # pragma: no cover
        """
        Returns a "prettified" string representing the SNMP message.
        """
        prefix = "  " * depth
        lines = [
            f"{prefix}{self.__class__.__name__} (tag: {self.TAG})",
            f"{prefix}  Request ID: {self.value.request_id}",
            f"{prefix}  Error Status: {self.value.error_status}",
            f"{prefix}  Error Index: {self.value.error_index}",
        ]
        if self.value.varbinds:
            lines.append(f"{prefix}  Varbinds: ")
            for bind in self.value.varbinds:
                lines.append(f"{prefix}    {bind.oid}: {bind.value}")
        else:
            lines.append(f"{prefix}  Varbinds: <none>")

        return "\n".join(lines)


class NoSuchObject(Type[bytes]):
    """
    Sentinel value to detect noSuchObject
    """

    # This subclassesPDU for type-consistency
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.PRIMITIVE]
    TAG = 0

    def __init__(self, value: bytes = b"") -> None:
        super().__init__(value)


class NoSuchInstance(Type[bytes]):
    """
    Sentinel value to detect noSuchInstance
    """

    # This subclassesPDU for type-consistency
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.PRIMITIVE]
    TAG = 1

    def __init__(self, value: bytes = b"") -> None:
        super().__init__(value)


class EndOfMibView(Type[bytes]):
    """
    Sentinel value to detect endOfMibView
    """

    # This subclassesPDU for type-consistency
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.PRIMITIVE]
    TAG = 2


class NoSuchOIDPacket(Type[bytes]):
    """
    Sentinel value to detect no-such-oid error
    """

    # This subclassesPDU for type-consistency
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.PRIMITIVE]
    TAG = 1

    def __init__(self, value: bytes = b"") -> None:
        super().__init__(value)


class GetRequest(PDU):
    """
    Represents an SNMP Get Request.
    """

    TAG = 0


class GetResponse(PDU):
    """
    Represents an SNMP basic response (this may be returned for other requests
    than GET as well).
    """

    TAG = 2


class GetNextRequest(GetRequest):
    """
    Represents an SNMP GetNext Request.
    """

    TAG = 1


class SetRequest(PDU):
    """
    Represents an SNMP SET Request.
    """

    TAG = 3


class BulkGetRequest(Type[Any]):
    """
    Represents a SNMP GetBulk request
    """

    # pylint: disable=abstract-method

    TYPECLASS = TypeClass.CONTEXT
    TAG = 5

    def __init__(self, request_id, non_repeaters, max_repeaters, *oids):
        # type: (int, int, int, ObjectIdentifier) -> None
        if len(oids) > MAX_VARBINDS:
            raise TooManyVarbinds(len(oids))
        self.request_id = request_id
        self.non_repeaters = non_repeaters
        self.max_repeaters = max_repeaters
        self.varbinds = []  # type: List[VarBind]
        for oid in oids:
            self.varbinds.append(VarBind(oid, Null()))

    def __bytes__(self) -> bytes:
        wrapped_varbinds = [Sequence([vb.oid, vb.value]) for vb in self.varbinds]  # type: ignore
        data: List[Type[Any]] = [
            Integer(self.request_id),
            Integer(self.non_repeaters),
            Integer(self.max_repeaters),
            Sequence(wrapped_varbinds),
        ]
        payload = b"".join([bytes(chunk) for chunk in data])

        tinfo = TypeInfo(TypeClass.CONTEXT, TypeNature.CONSTRUCTED, self.TAG)
        length = encode_length(len(payload))
        return bytes(tinfo) + length + payload

    def __repr__(self):
        # type: () -> str
        oids = [repr(oid) for oid, _ in self.varbinds]
        return "%s(%r, %r, %r, %s)" % (
            self.__class__.__name__,
            self.request_id,
            self.non_repeaters,
            self.max_repeaters,
            ", ".join(oids),
        )

    def __eq__(self, other):
        # type: (Any) -> bool
        # pylint: disable=unidiomatic-typecheck
        return (
            type(other) == type(self)
            and self.request_id == other.request_id
            and self.non_repeaters == other.non_repeaters
            and self.max_repeaters == other.max_repeaters
            and self.varbinds == other.varbinds
        )

    def pretty(self, depth: int = 0) -> str:  # pragma: no cover
        """
        Returns a "prettified" string representing the SNMP message.
        """
        prefix = "  " * depth
        lines = [
            f"{prefix}{self.__class__.__name__} (tag: {self.TAG})",
            f"{prefix}  Request ID: {self.request_id}",
            f"{prefix}  Non Repeaters: {self.non_repeaters}",
            f"{prefix}  Max Repeaters: {self.max_repeaters}",
            f"{prefix}  Varbinds: ",
        ]
        if self.varbinds:
            lines.append(f"{prefix}  Varbinds: ")
            for bind in self.varbinds:
                lines.append(f"{prefix}    {bind.oid}: {bind.value}")
        else:
            lines.append(f"{prefix}  Varbinds: <none>")

        return "\n".join(lines)


class InformRequest(PDU):
    """
    Represents an SNMP Inform request
    """

    TAG = 6


class Trap(PDU):
    """
    Represents an SNMP Trap
    """

    TAG = 7

    def __init__(self, *args, **kwargs):
        # type: (Any, Any) -> None
        super().__init__(*args, **kwargs)
        self.source = None  # type: Optional[SocketInfo]


class Report(PDU):
    """
    Represents an SNMP report
    """

    TAG = 8
