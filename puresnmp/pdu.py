"""
Model for SNMP PDUs (Request/Response messages).

PDUs all have a common structure, which is handled in the
:py:class:`~.PDU` class. The different (basic) PDU types only differ in
their type identifier header (f.ex. ``b'\\xa0'`` for a
:py:class:`~.GetRequest`).
"""

from dataclasses import dataclass
from typing import Any, List, Optional, Union, cast

from x690 import decode
from x690.types import (
    _SENTINEL_UNINITIALISED,
    UNINITIALISED,
    Integer,
    Null,
    ObjectIdentifier,
    Sequence,
    TWrappedPyType,
    Type,
)
from x690.util import TypeClass, TypeInfo, TypeNature, encode_length

from .const import MAX_VARBINDS
from .exc import EmptyMessage, ErrorResponse, TooManyVarbinds
from .typevars import SocketInfo
from .varbind import VarBind


@dataclass
class PDUContent:
    """
    A helper class to wrap PDU data into a single "value" variable for x.690
    types.
    """

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
        if not data:
            raise EmptyMessage("No data to decode!")
        request_id, nxt = decode(data, slc.start or 0, enforce_type=Integer)
        error_status, nxt = decode(data, nxt, enforce_type=Integer)
        error_index, nxt = decode(data, nxt, enforce_type=Integer)

        if error_status.value:
            error_detail, nxt = decode(data, nxt, enforce_type=Sequence)
            varbinds = [VarBind(oid, value) for oid, value in error_detail]  # type: ignore
            offending_oid = None
            if error_index.value != 0:
                offending_oid = varbinds[error_index.value - 1].oid
            exception = ErrorResponse.construct(
                error_status.value, offending_oid or ObjectIdentifier()
            )
            raise exception

        values, nxt = decode(data, nxt, enforce_type=Sequence)

        if not isinstance(values, Sequence):
            raise TypeError(
                "PDUs can only be decoded from sequences but got "
                "%r instead" % type(values)
            )

        varbinds = []
        for oid, value in values:  # type: ignore
            oid = cast(ObjectIdentifier, oid)  # type: ignore
            value = cast(Type[Any], value)  # type: ignore
            varbinds.append(VarBind(oid, value))

        return PDUContent(
            request_id.value, varbinds, error_status.value, error_index.value
        )

    def encode_raw(self) -> bytes:
        """
        Encodes this instance into raw x.690 bytes (excluding type & lenght)
        """

        wrapped_varbinds = [
            Sequence([vb.oid, vb.value]) for vb in self.value.varbinds
        ]
        data: List[Type[Any]] = [
            Integer(self.value.request_id),
            Integer(self.value.error_status),
            Integer(self.value.error_index),
            Sequence(wrapped_varbinds),  # type: ignore
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

    # pylint: disable=too-few-public-methods
    # |
    # | This class make exclusive use of the parent-implementation, only
    # | modifying class-level "type-detection" variables

    # This subclassesPDU for type-consistency
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.PRIMITIVE]
    TAG = 0

    def __init__(
        self,
        value: Union[TWrappedPyType, _SENTINEL_UNINITIALISED] = UNINITIALISED,
    ) -> None:
        if value is UNINITIALISED:
            super().__init__(value=b"")
        else:
            super().__init__(value=value)


class NoSuchInstance(Type[bytes]):
    """
    Sentinel value to detect noSuchInstance
    """

    # pylint: disable=too-few-public-methods
    # |
    # | This class make exclusive use of the parent-implementation, only
    # | modifying class-level "type-detection" variables

    # This subclassesPDU for type-consistency
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.PRIMITIVE]
    TAG = 1

    def __init__(
        self,
        value: Union[TWrappedPyType, _SENTINEL_UNINITIALISED] = UNINITIALISED,
    ) -> None:
        if value is UNINITIALISED:
            super().__init__(value=b"")
        else:
            super().__init__(value=value)


class EndOfMibView(Type[bytes]):
    """
    Sentinel value to detect endOfMibView
    """

    # pylint: disable=too-few-public-methods
    # |
    # | This class make exclusive use of the parent-implementation, only
    # | modifying class-level "type-detection" variables

    # This subclassesPDU for type-consistency
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.PRIMITIVE]
    TAG = 2


class NoSuchOIDPacket(Type[bytes]):
    """
    Sentinel value to detect no-such-oid error
    """

    # pylint: disable=too-few-public-methods
    # |
    # | This class make exclusive use of the parent-implementation, only
    # | modifying class-level "type-detection" variables

    # This subclassesPDU for type-consistency
    TYPECLASS = TypeClass.CONTEXT
    NATURE = [TypeNature.PRIMITIVE]
    TAG = 1

    def __init__(
        self,
        value: Union[TWrappedPyType, _SENTINEL_UNINITIALISED] = UNINITIALISED,
    ) -> None:
        if value is UNINITIALISED:
            super().__init__(value=b"")
        else:
            super().__init__(value=value)


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
            Sequence(wrapped_varbinds),  # type: ignore
        ]
        payload = b"".join([bytes(chunk) for chunk in data])

        tinfo = TypeInfo(TypeClass.CONTEXT, TypeNature.CONSTRUCTED, self.TAG)
        length = encode_length(len(payload))
        return bytes(tinfo) + length + payload

    def __repr__(self) -> str:
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
