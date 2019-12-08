"""
Utility functions for working with the X.690 and related standards.
"""
from __future__ import division, print_function, unicode_literals

from binascii import hexlify, unhexlify
from collections import namedtuple
from typing import TYPE_CHECKING

import six

from ..const import Length

if TYPE_CHECKING:  # pragma: no cover
    # pylint: disable=unused-import, cyclic-import
    from typing import Any, Dict, Iterable, List, Union, Tuple
    from .types import Type
    from puresnmp.typevars import PyType

if six.PY2:  # pragma: no cover

    def to_bytes(obj):
        # type: (Any) -> bytes
        """
        Converts an object to bytes.

        If it has a ``__bytes__`` attribute, uses this for conversion,
        otherwise converts first to ``bytearray``. This was only implemented
        for Python 2/3 consistency
        """
        if hasattr(obj, '__bytes__'):
            return bytes(obj)
        else:
            return bytes(bytearray(obj))

    def int_from_bytes(bytes_, byteorder, signed=False):
        # type: (bytes, str, bool) -> int
        """
        Converts a number to bytes
        """
        bytes_ = bytearray(bytes_)
        if byteorder == 'little':
            little_ordered = list(bytes_)
        elif byteorder == 'big':
            little_ordered = list(reversed(bytes_))
        n = sum(b << 8*i for i, b in enumerate(little_ordered))
        if signed and little_ordered and (little_ordered[-1] & 0x80):
            n -= 1 << 8*len(little_ordered)
        return n

else:
    unicode = str  # pylint: disable=invalid-name
    int_from_bytes = int.from_bytes  # pylint: disable=invalid-name

    def to_bytes(obj):
        # type: (Any) -> bytes
        """
        Converts an instance to bytes, and if it does not work, adds helpful
        details to the raised ``TypeError``
        """
        try:
            return bytes(obj)
        except TypeError as exc:
            raise TypeError(exc.args[0] + ' on type {}'.format(type(obj)))

LengthValue = namedtuple('LengthValue', 'length value')


class TypeInfo(namedtuple('TypeInfo', 'cls priv_const tag')):
    """
    Decoded structure for an X.690 "type" octet. Example::

        >>> TypeInfo.from_bytes(b'\\x30')
        TypeInfo(cls='universal', priv_const='constructed', tag=16)

    The structure contains 3 fields:

    cls
        The typeclass (either :py:attr:`~.UNIVERSAL`, :py:attr:`~.APPLICATION`,
        :py:attr:`~.CONTEXT` or :py:attr:`~.CONSTRUCTED`)

    priv_const
        Whether the value is :py:attr:`~.CONSTRUCTED` or :py:attr:`~.PRIMITIVE`

    tag
        The actual type identifier.

    The instance also keeps the raw value as it was seen in the ``_raw_value``
    attribute.
    """

    UNIVERSAL = 'universal'
    APPLICATION = 'application'
    CONTEXT = 'context'
    PRIVATE = 'private'
    PRIMITIVE = 'primitive'
    CONSTRUCTED = 'constructed'
    _raw_value = None

    @staticmethod
    def from_bytes(data):
        # type: ( Union[int, bytes] ) -> TypeInfo
        """
        Given one octet, extract the separate fields and return a TypeInfo
        instance::

            >>> TypeInfo.from_bytes(b'\\x30')
            TypeInfo(cls='universal', priv_const='constructed', tag=16)
        """
        # pylint: disable=attribute-defined-outside-init

        if isinstance(data, (bytes, bytearray)):
            data = int_from_bytes(data, 'big')
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
        # type: () -> bytes
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
        return to_bytes([output])

    if six.PY2:  # pragma: no cover
        def __unicode__(self):
            return repr(self)

        def __str__(self):
            return self.__bytes__()


def encode_length(value):
    # type: (int) -> bytes
    """
    This function encodes the length of a variable into bytes conforming to the
    rules defined in :term:`X.690`: The "length" field must be specially
    encoded for values above 127.  Additionally, from :term:`X.690`:

        8.1.3.2 A sender shall:

            a) use the definite form (see 8.1.3.3) if the encoding is
               primitive;
            b) use either the definite form (see 8.1.3.3) or the indefinite
               form (see 8.1.3.6), a sender's option, if the encoding is
               constructed and all immediately available;
            c) use the indefinite form (see 8.1.3.6) if the encoding is
               constructed and is not all immediately available.

    See also: https://en.wikipedia.org/wiki/X.690#Length_octets

    Example::

        >>> encode_length(16)    # no need for special encoding.
        b'\\x10'
        >>> encode_length(200)   # > 127, needs to be specially encoded.
        b'\\x81\\xc8'
    """
    if value == Length.INDEFINITE:
        return to_bytes([0b10000000])

    if value < 127:
        return to_bytes([value])

    output = []  # type: List[int]
    while value > 0:
        value, remainder = value // 256, value % 256
        output.insert(0, remainder)

    # prefix length information
    output = [0b10000000 | len(output)] + output
    return to_bytes(output)


def decode_length(data):
    # type: ( bytes ) -> LengthValue
    """
    Given a bytes object, which starts with the length information of a TLV
    value, returns a namedtuple with the length and the remaining bytes. So,
    given a TLV value, this function takes the "LV" part as input, parses the
    length information and returns the length plus the remaining "V" part
    (including any subsequent bytes).

    For values which are longer than 127 bytes, the length must be encoded into
    an unknown amount of "length" bytes. This function reads as many bytes as
    needed for the length. The return value contains the parsed length in
    number of bytes, and the remaining data bytes which follow the length
    bytes.

    Examples::

        >>> # length > 127, consume multiple length bytes
        >>> decode_length(b'\\x81\\xc8...')
        LengthValue(length=200, value=b'...')

        >>> # length <= 127, consume one length byte
        >>> decode_length(b'\\x10...')
        LengthValue(length=16, value=b'...')

    TODO: Upon rereading this, I wonder if it would not make more sense to take
          the complete TLV content as input.
    """
    data0 = six.byte2int(data)
    if data0 == 0b11111111:
        # reserved
        raise NotImplementedError('This is a reserved case in X690')

    if data0 & 0b10000000 == 0:
        # definite short form
        output = int_from_bytes([data0], 'big')
        data = data[1:]
    elif data0 ^ 0b10000000 == 0:
        # indefinite form
        raise NotImplementedError('Indefinite lenghts are '
                                  'not yet implemented!')
    else:
        # definite long form
        num_octets = int_from_bytes([data0 ^ 0b10000000], 'big')
        value_octets = data[1:1+num_octets]
        output = int_from_bytes(value_octets, 'big')
        data = data[num_octets + 1:]
    return LengthValue(output, data)


def visible_octets(data):
    # type: ( bytes ) -> str
    """
    Returns a geek-friendly (hexdump)  output of a bytes object.

    Developer note:
        This is not super performant. But it's not something that's supposed to
        be run during normal operations (mostly for testing and debugging).  So
        performance should not be an issue, and this is less obfuscated than
        existing solutions.

    Example::

        >>> from os import urandom
        >>> print(visible_octets(urandom(40)))
        99 1f 56 a9 25 50 f7 9b  95 7e ff 80 16 14 88 c5   ..V.%P...~......
        f3 b4 83 d4 89 b2 34 b4  71 4e 5a 69 aa 9f 1d f8   ......4.qNZi....
        1d 33 f9 8e f1 b9 12 e9                            .3......

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


def tablify(varbinds, num_base_nodes=0, base_oid=''):
    # type: ( Iterable[Tuple[Any, Any]], int, str ) -> List[Dict[str, Any]]
    """
    Converts a list of varbinds into a table-like structure. *num_base_nodes*
    can be used for table which row-ids consist of multiple OID tree nodes. By
    default, the last node is considered the row ID, and the second-last is the
    column ID. Example:

    By default, for the table-cell at OID ``1.2.3.4.5``, ``4`` is the column
    index and ``5`` is the row index.

    Using ``num_base_nodes=2`` will only use the first two nodes (``1.2``) as
    table-identifier, so ``3`` becomes the column index, and ``4.5`` becomes
    the row index.

    The output should *not* be considered ordered in any way. If you need it
    sorted, you must sort it after retrieving the table from this function!

    Each element of the output is a dictionary where each key is the column
    index. By default the index ``0`` will be added, representing the row ID.

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
    if isinstance(base_oid, str) and base_oid:
        # This import needs to be delayed to avoid circular imports
        from puresnmp.x690.types import ObjectIdentifier
        base_oid_parsed = ObjectIdentifier.from_string(base_oid)
        # Each table has a sub-index for the table "entry" so the number of
        # base-nodes needs to be incremented by 1
        num_base_nodes = len(base_oid_parsed)  #  type: ignore

    rows = {}  # type: Dict[str, Dict[str, Type[PyType]]]
    for oid, value in varbinds:
        if num_base_nodes:
            tail = oid.identifiers[num_base_nodes:]
            col_id, row_id = tail[0], tail[1:]
            row_id = '.'.join([unicode(node) for node in row_id])
        else:
            col_id = unicode(oid.identifiers[-2])
            row_id = unicode(oid.identifiers[-1])
        tmp = {
            '0': row_id,
        }
        row = rows.setdefault(row_id, tmp)
        row[unicode(col_id)] = value
    return list(rows.values())
