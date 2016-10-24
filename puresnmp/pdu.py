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

from .const import MAX_VARBINDS
from .exc import SnmpError, EmptyMessage, NoSuchOID, TooManyVarbinds
from .x690.types import (
    Integer,
    Null,
    ObjectIdentifier,
    Sequence,
    Type,
    encode_length,
    pop_tlv,
)
from .x690.util import TypeInfo


class VarBind(namedtuple('VarBind', 'oid, value')):

    def __new__(cls, oid, value):
        if not isinstance(oid, (ObjectIdentifier, str)):
            raise TypeError('OIDs for VarBinds must be ObjectIdentifier or str'
                            ' instances!')
        if isinstance(oid, str):
            oid = ObjectIdentifier.from_string(oid)
        return super().__new__(cls, oid, value)


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
            msg = ERROR_MESSAGES.get(error_status.value,
                                     'Unknown Error: %s' % error_status.value)
            # TODO Add detail from the error_index.
            raise SnmpError('Error packet received: %s!' % msg)
        values, data = pop_tlv(data)

        varbinds = [VarBind(*encoded_varbind) for encoded_varbind in values]

        return cls(
            request_id,
            varbinds,
            error_status,
            error_index
        )

    def __init__(self, request_id, varbinds, error_status=0, error_index=0):
        self.request_id = request_id
        self.error_status = error_status
        self.error_index = error_index
        if isinstance(varbinds, tuple):
            self.varbinds = [varbinds]
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
        payload = b''.join([bytes(chunk) for chunk in data])

        tinfo = TypeInfo(TypeInfo.CONTEXT, TypeInfo.CONSTRUCTED, self.TAG)
        length = encode_length(len(payload))
        return bytes(tinfo) + length + payload

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.request_id, self.varbinds)

    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        return (type(other) == type(self) and
                self.request_id == other.request_id and
                self.varbinds == other.varbinds)

    def pretty(self) -> str:  # pragma: no cover
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
        if len(oids) > MAX_VARBINDS:
            raise TooManyVarbinds(len(oids))
        wrapped_oids = []
        for oid in oids:
            if isinstance(oid, str):
                wrapped_oids.append(ObjectIdentifier.from_string(oid))
            else:
                wrapped_oids.append(oid)
        super().__init__(request_id, [VarBind(oid, Null())
                                      for oid in wrapped_oids])


class GetResponse(PDU):
    """
    Represents an SNMP basic response (this may be returned for other requests
    than GET as well).
    """
    TAG = 2

    @classmethod
    def decode(cls, data):
        """
        Try decoding the response. If nothing was returned (the message was
        empty), raise a :py:exc:`~puresnmp.exc.NoSuchOID` exception.
        """
        try:
            return super().decode(data)
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

    @classmethod
    def decode(cls, data):
        """
        This method takes a :py:class:`bytes` object and converts it to
        an application object.
        """
        # TODO (advanced): recent tests revealed that this is *not symmetric*
        # with __bytes__ of this class. This should be ensured!
        if not data:
            raise EmptyMessage('No data to decode!')
        request_id, data = pop_tlv(data)
        non_repeaters, data = pop_tlv(data)
        max_repeaters, data = pop_tlv(data)
        values, data = pop_tlv(data)

        oids = [str(*oid) for oid, _ in values]

        return cls(
            request_id,
            non_repeaters,
            max_repeaters,
            *oids
        )

    def __init__(self, request_id, non_repeaters, max_repeaters, *oids):
        if len(oids) > MAX_VARBINDS:
            raise TooManyVarbinds(len(oids))
        self.request_id = request_id
        self.non_repeaters = non_repeaters
        self.max_repeaters = max_repeaters
        self.varbinds = []
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
        payload = b''.join([bytes(chunk) for chunk in data])

        tinfo = TypeInfo(TypeInfo.CONTEXT, TypeInfo.CONSTRUCTED, self.TAG)
        length = encode_length(len(payload))
        return bytes(tinfo) + length + payload

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.request_id, self.varbinds)

    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        return (type(other) == type(self) and
                self.request_id == other.request_id and
                self.non_repeaters == other.non_repeaters and
                self.max_repeaters == other.max_repeaters and
                self.varbinds == other.varbinds)

    def pretty(self) -> str:  # pragma: no cover
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
