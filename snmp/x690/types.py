"""
See X690: https://en.wikipedia.org/wiki/X.690
"""

from collections import namedtuple

from ..exc import SnmpError
from .util import consume_length, encode_length


class TypeInfo(namedtuple('TypeInfo', 'cls pc tag')):

    UNIVERSAL = 'universal'
    APPLICATION = 'application'
    CONTEXT = 'context'
    PRIVATE = 'private'
    PRIMITIVE = 'primitive'
    CONSTRUCTED = 'constructed'

    @staticmethod
    def from_bytes(data):
        if data == 0b11111111:
            raise NotImplementedError('Long identifier types are not yet '
                                      'implemented')
        cls_hint = (data & 0b11000000) >> 6
        pc_hint = (data & 0b00100000) >> 5
        value = data & 0b00011111

        if cls_hint == 0b00:
            cls = TypeInfo.UNIVERSAL
        elif cls_hint == 0b01:
            cls = TypeInfo.APPLICATION
        elif cls_hint == 0b10:
            cls = TypeInfo.CONTEXT
        elif cls_hint == 0b11:
            cls = TypeInfo.PRIVATE
        else:
            raise ValueError('Unexpected value %r for type class' % bin(
                cls_hint))

        pc = TypeInfo.CONSTRUCTED if pc_hint else TypeInfo.PRIMITIVE

        instance = TypeInfo(cls, pc, value)
        instance._raw_value = data
        return instance

    def __bytes__(self):
        if self.cls == TypeInfo.UNIVERSAL:
            cls = 0b00
        elif self.cls == TypeInfo.APPLICATION:
            cls = 0b01
        elif self.cls == TypeInfo.CONTEXT:
            cls = 0b10
        elif self.cls == TypeInfo.PRIVATE:
            cls = 0b11
        else:
            raise ValueError('Unexpected class for type info')

        if self.pc == TypeInfo.CONSTRUCTED:
            pc = 0b01
        elif self.pc == TypeInfo.PRIMITIVE:
            pc = 0b00
        else:
            raise ValueError('Unexpected primitive/constructed for type info')

        output = cls << 6 | pc << 5 | self.tag
        return bytes([output])

    def __eq__(self, other):
        if isinstance(other, int):
            return self._raw_value == other
        elif isinstance(self, int):
            return self == other._raw_value
        else:
            return super().__eq__(other)


class Registry(type):

    __registry = {}

    def __new__(cls, name, parents, dict_):
        new_cls = super(Registry, cls).__new__(cls, name, parents, dict_)
        if hasattr(new_cls, 'TAG'):
            Registry.__registry[(new_cls.TYPECLASS, new_cls.TAG)] = new_cls
        return new_cls

    @staticmethod
    def get(typeclass, typeid):
        return Registry.__registry[(typeclass, typeid)]


def consume(data):
    """
    Inspects the next value in the data chunk. Returns the value and the
    remaining octets.
    """
    if not data:
        return None, b''
    type = TypeInfo.from_bytes(data[0])
    try:
        cls = Registry.get(type.cls, type.tag)
    except KeyError as exc:
        # Add context information
        raise KeyError('No class found for byte 0x%02x (%s)' % (
            data[0], exc))
    length, remainder = consume_length(data[1:])
    offset = len(data) - len(remainder)  # how many octets are used to encode the length
    chunk = data[:length+offset]
    value = cls.from_bytes(chunk)
    return value, remainder[length:]


class Type(metaclass=Registry):
    TYPECLASS = TypeInfo.UNIVERSAL

    @classmethod
    def validate(cls, data):
        tinfo = TypeInfo.from_bytes(data[0])
        if tinfo.cls != cls.TYPECLASS or tinfo.tag != cls.TAG:
            raise ValueError('Invalid type header! '
                             'Expected "universal" tag '
                             'with ID 0x%02x, got ID 0x%02x' % (
                                 cls.TAG, data[0]))

    @classmethod
    def from_bytes(cls, data):
        """
        Given a bytes object, this method reads the type information and length
        and uses it to convert the bytes representation into a python object.
        """
        cls.validate(data)
        expected_length, data = consume_length(data[1:])
        if not data:
            return None
        if len(data) != expected_length:
            raise ValueError('Corrupt packet: Unexpected length for {0} '
                             'Expected {1} (0x{1:02x}) '
                             'but got {2} (0x{2:02x})'.format(
                                 cls, expected_length, len(data)))

        return cls.decode(data)

    @classmethod
    def decode(cls, data):
        """
        This method takes a bytes object which contains the raw content octets
        of the object. That means, the octets *without* the type information and
        length.
        """
        raise NotImplementedError('Decoding is not yet implemented on %s' % cls)

    def __bytes__(self):
        raise NotImplementedError('Not yet implemented')

    def pythonize(self):
        return self.value


class Boolean(Type):
    TAG = 0x01

    @staticmethod
    def decode(data):
        return Boolean(data != b'\x00')

    @classmethod
    def validate(cls, data):
        super().validate(data)
        if data[1] != 1:
            raise ValueError('Unexpected Boolean value. Lenght should be 1, it '
                             'was %d' % data[1])

    def __init__(self, value):
        self.value = value

    def __bytes__(self):
        return bytes([1, 1, int(self.value)])

    def __repr__(self):
        return 'Boolean(%r)' % bool(self.value)

    def __eq__(self, other):
        return type(self) == type(other) and self.value == other.value


class Null(Type):
    TAG = 0x05

    @classmethod
    def validate(cls, data):
        super().validate(data)
        if data[1] != 0:
            raise ValueError('Unexpected NULL value. Lenght should be 0, it '
                             'was %d' % data[1])

    @classmethod
    def decode(data):
        return Null()

    def __bytes__(self):
        return b'\x05\x00'

    def __eq__(self, other):
        return type(self) == type(other)

    def __repr__(self):
        return 'Null()'


class OctetString(Type):
    TAG = 0x04

    @classmethod
    def decode(cls, data):
        return cls(data)

    def __init__(self, value):
        if isinstance(value, str):
            self.value = value.encode('ascii')
        else:
            self.value = value
        self.length = encode_length(len(value))

    def __bytes__(self):
        return (bytes([OctetString.TAG]) + self.length + self.value)

    def __repr__(self):
        return 'OctetString(%r)' % self.value

    def __eq__(self, other):
        return type(self) == type(other) and self.value == other.value

    def pythonize(self):
        """
        Convert this object in an appropriate python object
        """
        return self.value


class Sequence(Type):
    TAG = 0x10

    @classmethod
    def decode(cls, data):
        output = []
        while data:
            value, data = consume(data)
            if value is None:
                break
            output.append(value)
        return Sequence(*output)

    def __init__(self, *items):
        self.items = items

    def __bytes__(self):
        output = [bytes(item) for item in self.items]
        output = b''.join(output)
        length = encode_length(len(output))
        tinfo = TypeInfo(TypeInfo.UNIVERSAL, TypeInfo.CONSTRUCTED, Sequence.TAG)
        return bytes(tinfo) + length + output

    def __eq__(self, other):
        return type(self) == type(other) and self.items == other.items

    def __repr__(self):
        item_repr = [repr(item) for item in self.items]
        return 'Sequence(%s)' % ', '.join(item_repr)

    def pythonize(self):
        return [obj.pythonize() for obj in self.items]


class Integer(Type):
    TAG = 0x02

    @classmethod
    def decode(cls, data):
        return cls(int.from_bytes(data, 'big'))

    def __init__(self, value):
        self.value = value

    def __bytes__(self):
        if self.value == 0:
            octets = [0]
        else:
            remainder = self.value
            octets = []
            while remainder:
                octet = remainder & 0b11111111
                remainder = remainder >> 8
                octets.append(octet)
            octets.reverse()
        tinfo = TypeInfo(self.TYPECLASS, TypeInfo.PRIMITIVE, self.TAG)
        return bytes(tinfo) + bytes([len(octets)]) + bytes(octets)

    def __eq__(self, other):
        return type(self) == type(other) and self.value == other.value

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.value)


class ObjectIdentifier(Type):
    TAG = 0x06

    @staticmethod
    def decode_large_value(current_char, stream):
        """
        If we encounter a value larger than 127, we have to consume from the
        stram until we encounter a value below 127 and recombine them.

        See: https://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx
        """
        buffer = []
        while current_char > 127:
            buffer.append(current_char ^ 0b10000000)
            current_char = next(stream)
        total = current_char
        for i, digit in enumerate(reversed(buffer)):
            total += digit * 128**(i+1)
        return total

    @staticmethod
    def encode_large_value(value):
        if value <= 127:
            return [value]
        output = [value & 0b1111111]
        value = value >> 7
        while value:
            output.append(value & 0b1111111 | 0b10000000)
            value = value >> 7
        output.reverse()
        return output

    @classmethod
    def decode(cls, data):
        # unpack the first byte into first and second sub-identifiers.
        first, second = data[0] // 40, data[0] % 40
        output = [first, second]

        remaining = iter(data[1:])

        for char in remaining:
            # Each node can only contain values from 0-127. Other values need to
            # be combined.
            if char > 127:
                collapsed_value = ObjectIdentifier.decode_large_value(
                    char, remaining)
                output.append(collapsed_value)
                continue
            output.append(char)

        return ObjectIdentifier(*output)

    @staticmethod
    def from_string(value):
        """
        Create an OID from a string
        """

        if value == '.':
            return ObjectIdentifier(1)

        identifiers = [int(ident, 10) for ident in value.split('.')]
        return ObjectIdentifier(*identifiers)

    def __init__(self, *identifiers):
        # If the user hands in an iterable, instead of positional arguments,
        # make sure we unpack it
        if len(identifiers) == 1 and not isinstance(identifiers[0], int):
            identifiers = identifiers[0]

        if len(identifiers) > 1:
            # The first two bytes are collapsed according to X.690
            # See https://en.wikipedia.org/wiki/X.690#BER_encoding
            first, second, rest = identifiers[0], identifiers[1], identifiers[2:]
            first_output = (40*first) + second
        else:
            first_output = 1
            rest = []

        # Values above 127 need a special encoding. They get split up into
        # multiple positions.
        exploded_high_values = []
        for char in rest:
            if char > 127:
                exploded_high_values.extend(
                    ObjectIdentifier.encode_large_value(char))
            else:
                exploded_high_values.append(char)

        self.identifiers = identifiers
        self.__collapsed_identifiers = [first_output]
        for subidentifier in rest:
            self.__collapsed_identifiers.extend(
                ObjectIdentifier.encode_large_value(subidentifier))
        self.length = encode_length(len(self.__collapsed_identifiers))

    def __bytes__(self):
        return bytes([self.TAG]) + self.length + bytes(
            self.__collapsed_identifiers)

    def __str__(self):
        return '.'.join([str(_) for _ in self.identifiers])

    def __repr__(self):
        return 'ObjectIdentifier(%r)' % (self.identifiers, )

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.__collapsed_identifiers == other.__collapsed_identifiers)

    def pythonize(self):
        return '.'.join([str(_) for _ in self.identifiers])


class ObjectDescriptor(Type):
    TAG = 0x07


class External(Type):
    TAG = 0x08


class Real(Type):
    TAG = 0x09


class Enumerated(Type):
    TAG = 0x0a


class EmbeddedPdv(Type):
    TAG = 0x0b


class Utf8String(Type):
    TAG = 0x0c


class RelativeOid(Type):
    TAG = 0x0d


class Set(Type):
    TAG = 0x11


class NumericString(Type):
    TAG = 0x12


class PrintableString(Type):
    TAG = 0x13


class T61String(Type):
    TAG = 0x14


class VideotexString(Type):
    TAG = 0x15


class IA5String(Type):
    TAG = 0x16


class UtcTime(Type):
    TAG = 0x17


class GeneralizedTime(Type):
    TAG = 0x18


class GraphicString(Type):
    TAG = 0x19


class VisibleString(Type):
    TAG = 0x1a


class GeneralString(Type):
    TAG = 0x1b


class UniversalString(Type):
    TAG = 0x1c


class CharacterString(Type):
    TAG = 0x1d


class BmpString(Type):
    TAG = 0x1e


class Raw(Type):
    """
    This type is used to encapsulate raw bytes. This can be used if no specific
    type exists (yet).
    """

    @staticmethod
    def from_bytes(data):
        octets = [int.from_bytes(char) for char in data]
        return Raw(*octets)

    def __init__(self, *octets):
        self.octets = octets

    def __bytes__(self):
        return bytes(self.octets)


class EOC(Type):
    TAG = 0x00


class BitString(Type):
    TAG = 0x03


# --- SMI

class TimeTicks(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x03

class Gauge(Integer):
    TYPECLASS = TypeInfo.APPLICATION
    TAG = 0x02


# --- Requests

class RequestResponsePacket(Type):

    @classmethod
    def validate(cls, data):
        tinfo = TypeInfo.from_bytes(data[0])
        if tinfo.cls != TypeInfo.CONTEXT or tinfo.tag != cls.TAG:
            raise ValueError(
                'Invalid type header! '
                'Expected "context" tag with ID 0x%02x, '
                'got ID 0x%02x' % (cls.TAG, data[0]))


class GetRequest(RequestResponsePacket):
    TYPECLASS, _, TAG = TypeInfo.from_bytes(0xa0)

    def __init__(self, oid, request_id):
        self.request_id = request_id
        self.oid = oid

    def __bytes__(self):
        data = [
            Integer(self.request_id),
            Integer(0),
            Integer(0),
            Sequence(
                Sequence(
                    self.oid,
                    Null(),
                )
            )
        ]
        payload = b''.join([bytes(chunk) for chunk in data])

        tinfo = TypeInfo(TypeInfo.CONTEXT, TypeInfo.CONSTRUCTED, self.TAG)
        length = encode_length(len(payload))
        return bytes(tinfo) + length + payload


class GetResponse(RequestResponsePacket):
    TYPECLASS, _, TAG = TypeInfo.from_bytes(0xa2)

    def __init__(self, request_id, oid, value):
        self.request_id = request_id
        self.oid = oid
        self.value = value

    @classmethod
    def decode(cls, data):
        request_id, data = consume(data)
        error_code, data = consume(data)
        error_index, data = consume(data)
        if error_code.value:
            raise SnmpError('Error packet received!')  # TODO Add detail.
        values, data = consume(data)

        # TODO the following index fiddling is ugly!
        if len(values.items[0].items) == 1:
            # empty result
            value = None
        else:
            value = values.items[0].items[1]

        return GetResponse(
            request_id,
            values.items[0].items[0],
            value,
        )

    def __repr__(self):
        return 'GetResponse(%r, %r, %r)' % (
            self.request_id, self.oid, self.value)

    def __eq__(self, other):
        return (type(other) == type(self) and
                self.request_id == other.request_id and
                self.oid == other.oid and
                self.value == other.value)


class GetNextRequest(GetRequest):
    TYPECLASS, _, TAG = TypeInfo.from_bytes(0xa1)
