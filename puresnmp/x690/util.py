"""
Core/low-level x690 functions and data structures
"""


from binascii import hexlify, unhexlify
from collections import namedtuple
from typing import Tuple, Union


class TypeInfo(namedtuple('TypeInfo', 'cls priv_const tag')):
    """
    Decoded structure for an x690 "type" octet. The structure contains 3 fields:

    cls
        The typeclass (either TypeInfo.UNIVERSAL, TypeInfo.APPLICATION,
        TypeInfo.CONTEXT or TypeInfo.CONSTRUCTED)

    priv_const
        Whether the value is TypeInfo.CONSTRUCTED or TypeInfo.PRIMITIVE

    tag
        The actual type identifier.
    """

    UNIVERSAL = 'universal'
    APPLICATION = 'application'
    CONTEXT = 'context'
    PRIVATE = 'private'
    PRIMITIVE = 'primitive'
    CONSTRUCTED = 'constructed'

    @staticmethod
    def from_bytes(data: Union[int, bytes]) -> "TypeInfo":
        """
        Given one octet, extract the separate fields and return a TypeInfo
        instance.
        """
        if isinstance(data, bytes):
            data = int.from_bytes(data, 'big')
        # pylint: disable=protected-access
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
            pass  # Impossible case (2 bits can only have 4 combinations).

        priv_const = TypeInfo.CONSTRUCTED if pc_hint else TypeInfo.PRIMITIVE

        instance = TypeInfo(cls, priv_const, value)
        instance._raw_value = data
        return instance

    def __bytes__(self):
        # pylint: disable=invalid-name
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

        if self.priv_const == TypeInfo.CONSTRUCTED:
            priv_const = 0b01
        elif self.priv_const == TypeInfo.PRIMITIVE:
            priv_const = 0b00
        else:
            raise ValueError('Unexpected primitive/constructed for type info')

        output = cls << 6 | priv_const << 5 | self.tag
        return bytes([output])

    def __eq__(self, other):
        return super().__eq__(other)


class Length:
    """
    A simple "namespace" to avoid magic values for indefinite lengths.
    """
    INDEFINITE = "indefinite"


def encode_length(value):
    """
    The "length" field must be specially encoded for values above 127.
    Additionally, from X.690:

        8.1.3.2 A sender shall:

            a) use the definite form (see 8.1.3.3) if the encoding is primitive;
            b) use either the definite form (see 8.1.3.3) or the indefinite form
               (see 8.1.3.6), a sender's option, if the encoding is constructed
               and all immediately available;
            c) use the indefinite form (see 8.1.3.6) if the encoding is
               constructed and is not all immediately available.

    See also: https://en.wikipedia.org/wiki/X.690#Length_octets
    """
    if value == Length.INDEFINITE:
        return bytes([0b10000000])

    if value < 127:
        return bytes([value])

    output = []
    while value > 0:
        value, remainder = value // 256, value % 256
        output.append(remainder)

    # prefix length information
    output = [0b10000000 | len(output)] + output
    return bytes(output)


def decode_length(data: bytes) -> Tuple[int, bytes]:
    """
    Given a bytes object, which starts with the length information of a TLV
    value, returns the length and the remaining bytes. So, given a TLV value,
    this function takes the "LV" part as input, parses the length information
    and returns the remaining "V" part (including any subsequent bytes).

    TODO: Upon rereading this, I wonder if it would not make more sense to take
          the complete TLV content as input.
    """
    if data[0] == 0b11111111:
        # reserved
        raise NotImplementedError('This is a reserved case in X690')
    elif data[0] & 0b10000000 == 0:
        # definite short form
        output = int.from_bytes([data[0]], 'big')
        data = data[1:]
    elif data[0] ^ 0b10000000 == 0:
        # indefinite form
        raise NotImplementedError('Indefinite lenghts are not yet implemented!')
    else:
        # definite long form
        num_octets = int.from_bytes([data[0] ^ 0b10000000], 'big')
        value_octets = data[1:1+num_octets]
        output = int.from_bytes(value_octets, 'big')
        data = data[num_octets + 1:]
    return output, data


def visible_octets(data: bytes) -> str:
    """
    Returns a geek-friendly (hexdump)  output of a bytes object.

    Developer note:
        This is not super performant. But it's not something that's supposed to
        be run during normal operations (mostly for testing and debugging).  So
        performance should not be an issue, and this is less obfuscated than
        existing solutions.
    """
    hexed = hexlify(data).decode('ascii')
    tuples = [''.join((a, b)) for a, b in zip(hexed[::2], hexed[1::2])]
    line = []
    output = []
    ascii = []
    for idx, octet in enumerate(tuples):
        line.append(octet)
        # only use printable characters in ascii output
        ascii.append(octet if 32 <= int(octet, 16) < 127 else '2e')
        if (idx+1) % 8 == 0:
            line.append('')
        if (idx+1) % 8 == 0 and (idx+1) % 16 == 0:
            raw_ascii = unhexlify(''.join(ascii))
            raw_ascii = raw_ascii.replace(b'\\n z', b'.')
            ascii = []
            output.append('%-50s %s' % (' '.join(line),
                                        raw_ascii.decode('ascii')))
            line = []
    raw_ascii = unhexlify(''.join(ascii))
    raw_ascii = raw_ascii.replace(b'\\n z', b'.')
    output.append('%-50s %s' % (' '.join(line), raw_ascii.decode('ascii')))
    line = []
    return '\n'.join(output)
