"""
Core/low-level x690 functions and data structures
"""
from binascii import hexlify, unhexlify
from collections import namedtuple
from typing import Tuple, Union, List, Any


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
        # pylint: disable=attribute-defined-outside-init

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
    # pylint: disable=too-few-public-methods

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
    ascii_column = []
    for idx, octet in enumerate(tuples):
        line.append(octet)
        # only use printable characters in ascii output
        ascii_column.append(octet if 32 <= int(octet, 16) < 127 else '2e')
        if (idx+1) % 8 == 0:
            line.append('')
        if (idx+1) % 8 == 0 and (idx+1) % 16 == 0:
            raw_ascii = unhexlify(''.join(ascii_column))
            raw_ascii = raw_ascii.replace(b'\\n z', b'.')
            ascii_column = []
            output.append('%-50s %s' % (' '.join(line),
                                        raw_ascii.decode('ascii')))
            line = []
    raw_ascii = unhexlify(''.join(ascii_column))
    raw_ascii = raw_ascii.replace(b'\\n z', b'.')
    output.append('%-50s %s' % (' '.join(line), raw_ascii.decode('ascii')))
    line = []
    return '\n'.join(output)


def tablify(varbinds: List[Tuple[Any, Any]], num_base_nodes: int=0) -> list:
    """
    Converts a list of varbinds into a table-like structure. *num_base_nodes*
    can be used for table which row-ids consist of multiple OID tree nodes. By
    default, the last node is considered the row ID, and the second-last is the
    column ID.

    The output should *not* be considered ordered in any way. If you need it
    sorted, you mus sort it after retrieving the table from this function!

    Each element of the output is a dictionary where each key is the column
    index. By default the index ``0`` represents the row ID.

    Example::

        >>> data = [
        >>>     (ObjectIdentifier.from_string('1.2.1.1'), 'row 1 col 1'),
        >>>     (ObjectIdentifier.from_string('1.2.1.2'), 'row 2 col 1'),
        >>>     (ObjectIdentifier.from_string('1.2.2.1'), 'row 1 col 2'),
        >>>     (ObjectIdentifier.from_string('1.2.2.2'), 'row 2 col 2'),
        >>> ]
        >>> tablify(data)
        [
            {'0': '1', '1': 'row 1 col 1', '2': 'row 1 col 2'},
            {'0': '2', '1': 'row 2 col 1', '2': 'row 2 col 2'},
        ]


    Example with longer row ids (using the *first* two as table identifiers)::

        >>> data = [
        >>>     (ObjectIdentifier.from_string('1.2.1.5.10'), 'row 5.10 col 1'),
        >>>     (ObjectIdentifier.from_string('1.2.1.6.10'), 'row 6.10 col 1'),
        >>>     (ObjectIdentifier.from_string('1.2.2.5.10'), 'row 5.10 col 2'),
        >>>     (ObjectIdentifier.from_string('1.2.2.6.10'), 'row 6.10 col 2'),
        >>> ]
        >>> tablify(data, num_base_nodes=2)
        [
            {'0': '5.10', '1': 'row 5.10 col 1', '2': 'row 5.10 col 2'},
            {'0': '6.10', '1': 'row 6.10 col 1', '2': 'row 6.10 col 2'},
        ]
    """
    rows = {}
    for oid, value in varbinds:
        if num_base_nodes:
            tail = oid.identifiers[num_base_nodes:]
            col_id, row_id = tail[0], tail[1:]
            row_id = '.'.join([str(node) for node in row_id])
        else:
            col_id, row_id = str(oid.identifiers[-2]), str(oid.identifiers[-1])
        tmp = {
            '0': row_id,
        }
        row = rows.setdefault(row_id, tmp)
        row[str(col_id)] = value
    return list(rows.values())
