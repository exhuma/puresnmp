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

from typing import TYPE_CHECKING, Any, Iterable, List, Tuple, Union, cast

from x690.types import Integer, Null, ObjectIdentifier, Sequence, Type, pop_tlv
from x690.util import TypeClass, TypeInfo, TypeNature, encode_length

from .const import MAX_VARBINDS
from .exc import EmptyMessage, ErrorResponse, NoSuchOID, TooManyVarbinds
from .snmp import VarBind
from .typevars import SocketInfo

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from typing import Iterator, Optional


class PDU(Type[Any]):
    """
    The superclass for SNMP Messages (GET, SET, GETNEXT, ...)
    """

    TYPECLASS = TypeClass.CONTEXT
    TAG = 0

    request_id: int
    error_status: int
    error_index: int
    varbinds: List[VarBind]

    @classmethod
    def decode(cls, data: bytes) -> "PDU":
        """
        This method takes a :py:class:`bytes` object and converts it to
        an application object. This is callable from each subclass of
        :py:class:`~.PDU`.
        """
        # TODO (advanced): recent tests revealed that this is *not symmetric*
        # with __bytes__ of this class. This should be ensured!
        if not data:
            raise EmptyMessage("No data to decode!")
        request_id, data = pop_tlv(data)
        error_status, data = pop_tlv(data)
        error_index, data = pop_tlv(data)
        if error_status.value:
            error_detail, data = cast(
                Tuple[Iterable[Tuple[ObjectIdentifier, int]], bytes],
                pop_tlv(data),
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
            assert data == b""
            exception = ErrorResponse.construct(
                error_status.value, offending_oid
            )
            raise exception

        values, data = cast(
            Tuple[Iterable[Tuple[ObjectIdentifier, int]], bytes], pop_tlv(data)
        )
        if not isinstance(values, Sequence):
            raise TypeError(
                "PDUs can only be decoded from sequences but got "
                "%r instead" % type(values)
            )

        varbinds = []
        for oid, value in values:
            # NOTE: this uses the "is" check to make 100% sure we check against
            # the sentinel object defined in this module!
            if value is END_OF_MIB_VIEW:
                varbinds.append(VarBind(oid, END_OF_MIB_VIEW))
                break
            varbinds.append(VarBind(oid, value))

        return cls(
            request_id.value, varbinds, error_status.value, error_index.value
        )

    def __init__(
        self,
        request_id: int,
        varbinds: Union[VarBind, List[VarBind]],
        error_status: int = 0,
        error_index: int = 0,
    ) -> None:
        self.request_id = request_id
        self.error_status = error_status
        self.error_index = error_index
        if isinstance(varbinds, VarBind):
            self.varbinds = [VarBind(*varbinds)]
        else:
            self.varbinds = varbinds

    def __bytes__(self) -> bytes:
        wrapped_varbinds = [Sequence(vb.oid, vb.value) for vb in self.varbinds]  # type: ignore
        data: List[Type[Any]] = [
            Integer(self.request_id),
            Integer(self.error_status),
            Integer(self.error_index),
            Sequence(*wrapped_varbinds),
        ]
        payload = b"".join([bytes(chunk) for chunk in data])

        tinfo = TypeInfo(TypeClass.CONTEXT, TypeNature.CONSTRUCTED, self.TAG)
        length = encode_length(len(payload))
        return bytes(tinfo) + length + payload

    def __repr__(self) -> str:
        return "%s(%r, %r)" % (
            self.__class__.__name__,
            self.request_id,
            self.varbinds,
        )

    def __eq__(self, other: Any) -> bool:
        # pylint: disable=unidiomatic-typecheck
        return (
            type(other) == type(self)
            and self.request_id == other.request_id
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
            f"{prefix}  Error Status: {self.error_status}",
            f"{prefix}  Error Index: {self.error_index}",
        ]
        if self.varbinds:
            lines.append(f"{prefix}  Varbinds: ")
            for bind in self.varbinds:
                lines.append(f"{prefix}    {bind.oid}: {bind.value}")
        else:
            lines.append(f"{prefix}  Varbinds: <none>")

        return "\n".join(lines)


class EndOfMibView(PDU):
    """
    Sentinel value to detect endOfMibView
    """

    # This subclassesPDU for type-consistency


#: Singleton instance of "EndOfMibView"
END_OF_MIB_VIEW = EndOfMibView(-1, [])


class GetRequest(PDU):
    """
    Represents an SNMP Get Request.
    """

    TAG = 0

    def __init__(
        self,
        request_id: int,
        varbinds: Union[VarBind, List[VarBind]],
        error_status: int = 0,
        error_index: int = 0,
    ) -> None:
        # GetRequest varbinds should use a "NULL" value. Let's ensure this.
        if isinstance(varbinds, VarBind):
            varbinds = [varbinds]
        varbinds = [VarBind(vb.oid, Null()) for vb in varbinds]
        super().__init__(request_id, varbinds)


class GetResponse(PDU):
    """
    Represents an SNMP basic response (this may be returned for other requests
    than GET as well).
    """

    TAG = 2

    @classmethod
    def decode(cls, data):
        # type: (bytes) -> PDU
        """
        Try decoding the response. If nothing was returned (the message was
        empty), raise a :py:exc:`~puresnmp.exc.NoSuchOID` exception.
        """
        # TODO This is not reslly clean, but it should work. A GetResponse has
        #      the same type identifier as a "endOfMibView" *value*. The way
        #      puresnmp is structured (recursively calling "pop_tlv") makes it
        #      difficult to distinguish between a valid GetResponse object and
        #      an endOfMibView value, except that the endOfMibView had no data.
        if not data:
            return END_OF_MIB_VIEW
        try:
            return super().decode(data)
        except EmptyMessage as exc:
            raise NoSuchOID(
                ObjectIdentifier(0), "Nothing found at the given OID (%s)" % exc
            ) from exc


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
        wrapped_varbinds = [Sequence(vb.oid, vb.value) for vb in self.varbinds]  # type: ignore
        data: List[Type[Any]] = [
            Integer(self.request_id),
            Integer(self.non_repeaters),
            Integer(self.max_repeaters),
            Sequence(*wrapped_varbinds),
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
