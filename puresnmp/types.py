"""
SMI Types / Structure types which are not defined in ASN.1
"""

from collections import namedtuple

from .exc import SnmpError
from .x690.types import Integer, Type, Sequence, Null, pop_tlv, encode_length
from .x690.util import TypeInfo


ERROR_MESSAGES = {
    0: '(noError)',
    1: '(tooBig)',
    2: '(noSuchName)',
    3: '(badValue)',
    4: '(readOnly)',
    5: '(genErr)',
}

VarBind = namedtuple('VarBind', 'oid, value')


class IpAddress(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x00


class Counter(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x01


class Gauge(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x02


class TimeTicks(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x03


class Opaque(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x04


class NsapAddress(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x05


# --- Requests / Responses

class SnmpMessage(Type):

    @classmethod
    def validate(cls, data):
        tinfo = TypeInfo.from_bytes(data[0])
        if tinfo.cls != TypeInfo.CONTEXT or tinfo.tag != cls.TAG:
            raise ValueError(
                'Invalid type header! '
                'Expected "context" tag with ID 0x%02x, '
                'got ID 0x%02x' % (cls.TAG, data[0]))

    @classmethod
    def decode(cls, data):
        request_id, data = pop_tlv(data)
        error_code, data = pop_tlv(data)
        error_index, data = pop_tlv(data)
        if error_code.value:
            msg = ERROR_MESSAGES.get(error_code.value,
                                     'Unknown Error: %s' % error_code.value)
            # TODO Add detail from the error_index.
            raise SnmpError('Error packet received: %s!' % msg)
        values, data = pop_tlv(data)

        varbinds = [VarBind(*encoded_varbind.items)
                    for encoded_varbind in values.items]

        return cls(
            request_id,
            varbinds,
            error_code,  # TODO rename to "error_status"
            error_index
        )

    def __init__(self, request_id, varbinds, error_status=0, error_index=0):
        self.request_id = request_id
        if isinstance(varbinds, tuple):
            self.varbinds = [varbinds]
        else:
            self.varbinds = varbinds
        self.error_status = error_status
        self.error_index = error_index

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
        return (type(other) == type(self) and
                self.request_id == other.request_id and
                self.varbinds == other.varbinds)


class GetRequest(SnmpMessage):
    TYPECLASS, _, TAG = TypeInfo.from_bytes(0xa0)

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__, self.request_id, self.varbinds)

    def __init__(self, request_id, *oids):
        super().__init__(request_id, [VarBind(oid, Null()) for oid in oids])


class GetResponse(SnmpMessage):
    TYPECLASS, _, TAG = TypeInfo.from_bytes(0xa2)


class GetNextRequest(GetRequest):
    TYPECLASS, _, TAG = TypeInfo.from_bytes(0xa1)


class SetRequest(SnmpMessage):
    TYPECLASS, _, TAG = TypeInfo.from_bytes(0xa3)
