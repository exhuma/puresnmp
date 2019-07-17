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

from collections import namedtuple
from typing import TYPE_CHECKING

import six

from .const import MAX_VARBINDS
from .exc import (
    EmptyMessage,
    ErrorResponse,
    NoSuchOID,
    SnmpError,
    TooManyVarbinds
)
from .x690.types import (
    Integer,
    Null,
    ObjectIdentifier,
    Sequence,
    Type,
    encode_length,
    pop_tlv
)
from .x690.util import TypeInfo, to_bytes

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from typing import List, Union


if six.PY3:
    unicode = str  # pylint: disable=invalid-name


#: Sentinel value to detect endOfMibView
END_OF_MIB_VIEW = object()


class VarBind(namedtuple('VarBind', 'oid, value')):
    '''
    A "VarBind" is a 2-tuple containing an object-identifier and the
    corresponding value.
    '''

    def __new__(cls, oid, value):
        if not isinstance(oid, (ObjectIdentifier,) + six.string_types):
            raise TypeError('OIDs for VarBinds must be ObjectIdentifier or str'
                            ' instances! Your value: %r' % oid)
        if isinstance(oid, six.string_types):
            oid = ObjectIdentifier.from_string(oid)
        return super(VarBind, cls).__new__(cls, oid, value)


ERROR_MESSAGES = {
    0: '(noError)',
    1: '(tooBig)',
    2: '(noSuchName)',
    3: '(badValue)',
    4: '(readOnly)',
    5: '(genErr)',
    6: '(noAccess)',
    7: '(wrongType)',
    8: '(wrongLength)',
    9: '(wrongEncoding)',
    10: '(wrongValue)',
    11: '(noCreation)',
    12: '(inconsistentValue)',
    13: '(resourceUnavailable)',
    14: '(commitFailed)',
    15: '(undoFailed)',
    16: '(authorizationError)',
    17: '(notWritable)',
    18: '(inconsistentName)'
}


class PDU(Type):
    """
    The superclass for SNMP Messages (GET, SET, GETNEXT, ...)
    """
    TYPECLASS = TypeInfo.CONTEXT

    @classmethod
    def decode(cls, data):
        # type: (bytes) -> PDU
        """
        This method takes a :py:class:`bytes` object and converts it to
        an application object. This is callable from each subclass of
        :py:class:`~.PDU`.
        """
        # TODO (advanced): recent tests revealed that this is *not symmetric*
        # with __bytes__ of this class. This should be ensured!
        if not data:
            raise EmptyMessage('No data to decode!')
        request_id, data = pop_tlv(data)
        error_status, data = pop_tlv(data)
        error_index, data = pop_tlv(data)
        if error_status.value:
            error_detail, data = pop_tlv(data)
            varbinds = [VarBind(*raw_varbind) for raw_varbind in error_detail]
            offending_oid = varbinds[error_index.value-1].oid
            assert data == b''
            exception = ErrorResponse.construct(
                error_status.value, offending_oid)
            raise exception

        values, data = pop_tlv(data)
        varbinds = []
        for oid, value in values:
            # NOTE: this uses the "is" check to make 100% sure we check against
            # the sentinel object defined in this module!
            if value is END_OF_MIB_VIEW:
                varbinds.append(VarBind(oid, END_OF_MIB_VIEW))
                break
            varbinds.append(VarBind(oid, value))

        return cls(
            request_id,
            varbinds,
            error_status,
            error_index
        )

    def __init__(self, request_id, varbinds, error_status=0, error_index=0):
        # type: (int, Union[tuple, List[VarBind]], int, int) -> None
        self.request_id = request_id
        self.error_status = error_status
        self.error_index = error_index
        if isinstance(varbinds, tuple):
            self.varbinds = [VarBind(*varbinds)]
        else:
            self.varbinds = varbinds

    def __bytes__(self):
        wrapped_varbinds = [Sequence(vb.oid, vb.value) for vb in self.varbinds]
        data = [
            Integer(self.request_id),
            Integer(self.error_status),
            Integer(self.error_index),
            Sequence(*wrapped_varbinds)
        ]
        payload = b''.join([to_bytes(chunk) for chunk in data])

        tinfo = TypeInfo(TypeInfo.CONTEXT, TypeInfo.CONSTRUCTED, self.TAG)
        length = encode_length(len(payload))
        return to_bytes(tinfo) + length + payload

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.request_id, self.varbinds)

    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        return (type(other) == type(self) and
                self.request_id == other.request_id and
                self.varbinds == other.varbinds)

    def pretty(self):  # pragma: no cover
        # type: () -> str
        """
        Returns a "prettified" string representing the SNMP message.
        """
        lines = [
            self.__class__.__name__,
            '    Request ID: %s' % self.request_id,
            '    Error Status: %s' % self.error_status,
            '    Error Index: %s' % self.error_index,
            '    Varbinds: ',
        ]
        for bind in self.varbinds:
            lines.append('        %s: %s' % (bind.oid, bind.value))

        return '\n'.join(lines)


class GetRequest(PDU):
    """
    Represents an SNMP Get Request.
    """
    TAG = 0

    def __init__(self, request_id, *oids):
        # type: (int, Union[str, ObjectIdentifier]) -> None
        if len(oids) > MAX_VARBINDS:
            raise TooManyVarbinds(len(oids))
        wrapped_oids = []
        for oid in oids:
            if isinstance(oid, str):
                wrapped_oids.append(ObjectIdentifier.from_string(oid))
            else:
                wrapped_oids.append(oid)
        super(GetRequest, self).__init__(request_id, [VarBind(oid, Null())
                                                      for oid in wrapped_oids])


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
            return super(GetResponse, cls).decode(data)
        except EmptyMessage as exc:
            raise NoSuchOID('Nothing found at the given OID (%s)' % exc)


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


class BulkGetRequest(Type):
    """
    Represents a SNMP GetBulk request
    """
    TYPECLASS = TypeInfo.CONTEXT
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

    def __bytes__(self):
        wrapped_varbinds = [Sequence(vb.oid, vb.value) for vb in self.varbinds]
        data = [
            Integer(self.request_id),
            Integer(self.non_repeaters),
            Integer(self.max_repeaters),
            Sequence(*wrapped_varbinds)
        ]
        payload = b''.join([to_bytes(chunk) for chunk in data])

        tinfo = TypeInfo(TypeInfo.CONTEXT, TypeInfo.CONSTRUCTED, self.TAG)
        length = encode_length(len(payload))
        return to_bytes(tinfo) + length + payload

    def __repr__(self):
        oids = [repr(oid) for oid, _ in self.varbinds]
        return '%s(%r, %r, %r, %s)' % (
            self.__class__.__name__,
            self.request_id,
            self.non_repeaters,
            self.max_repeaters,
            ', '.join(oids))

    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        return (type(other) == type(self) and
                self.request_id == other.request_id and
                self.non_repeaters == other.non_repeaters and
                self.max_repeaters == other.max_repeaters and
                self.varbinds == other.varbinds)

    def pretty(self):  # pragma: no cover
        # type () -> str
        """
        Returns a "prettified" string representing the SNMP message.
        """
        lines = [
            self.__class__.__name__,
            '    Request ID: %s' % self.request_id,
            '    Non Repeaters: %s' % self.non_repeaters,
            '    Max Repeaters: %s' % self.max_repeaters,
            '    Varbinds: ',
        ]
        for bind in self.varbinds:
            lines.append('        %s: %s' % (bind.oid, bind.value))

        return '\n'.join(lines)


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
