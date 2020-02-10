# type: ignore
# Type-Hinting is done in a stub file
"""
Overview
========

This module contains the encoding/decoding logic for data types as defined in
:term:`X.690`.

Each type is made available via a :py:class:`~.Registry` and can be retrieved
via :py:meth:`~.Registry.get`.

Additionally, given a :py:class:`bytes` object, the :py:func:`~.pop_tlv`
function can be used to parse theat bytes object and return a typed instance
from it. See :py:func:`~.pop_tlv` for details about it's behaviour!

.. note::
    The individual type classes in this module do not contain any additional
    documentation. The bulk of this module is documented in :py:class:`~.Type`
    and :py:class:`~.Registry`.

    For the rest, the type classes simply define the type identifier tag.

Supporting Additional Classes
=============================

Just by subclassing :py:class:`~.Type` and setting correct ``TAG`` and
``TYPECLASS`` values, most of the basic functionality will be covered by the
superclass. Type detection, and addition to the registry is automatic.
Subclassing is enough.

By default, a new type which does not override any methods will have it's value
reported as bytes objects. You may want to override at least
:py:meth:`~.Type.pythonize` to expose the value to users of the library as pure
Python objects.

Depending on type, you may also want to override certain methods. See
:py:class:`~.Sequence` and :py:class:`~.Integer` for more complex examples.
"""
# pylint: disable=abstract-method, missing-docstring

from __future__ import division, print_function, unicode_literals

import logging
import warnings

import six
import t61codec
from six.moves import zip_longest

from .exc import InvalidValueLength
from .util import (
    TypeInfo,
    decode_length,
    encode_length,
    int_from_bytes,
    to_bytes
)

try:
    unicode
except NameError:
    # pylint: disable=invalid-name
    unicode = str


LOG = logging.getLogger(__name__)


class Registry(type):

    __registry = {}

    def __new__(cls, name, parents, dict_):
        new_cls = super(Registry, cls).__new__(cls, name, parents, dict_)
        if hasattr(new_cls, 'TAG') and hasattr(new_cls, 'TYPECLASS'):
            Registry.__registry[(new_cls.TYPECLASS, new_cls.TAG)] = new_cls
        else:
            LOG.warning('Ignoring class %r. It is missing either the '
                        'TYPECLASS or TAG class attribute!', new_cls)
        return new_cls

    @staticmethod
    def get(typeclass, typeid):
        return Registry.__registry[(typeclass, typeid)]


def pop_tlv(data):
    """
    Given a :py:class:`bytes` object, inspects and parses the first octets (as
    many as required) to determine variable type (and corresponding Python
    class), and length. The class is then used to parse the *first* object in
    ``data``.  *data* itself will not be modified. Instead, a new modified copy
    of *data* is returned alongside the parsed object. This new object is the
    remainder after popping off the first object.

    Example::

        >>> data = b'\\x02\\x01\\x05\\x11'
        >>> pop_tlv(data)
        (Integer(5), b'\\x11')

    Note that in the example above, ``\\x11`` is the remainder of the bytes
    object after popping of the integer object.
    """
    # TODO: This function should be moved to another module (util maybe?).
    if not data:
        return Null(), b''
    type_ = TypeInfo.from_bytes(data[0])
    length, remainder = decode_length(data[1:])

    # determine how many octets are used to encode the length!
    offset = len(data) - len(remainder)
    chunk = data[:length+offset]
    try:
        cls = Registry.get(type_.cls, type_.tag)
        value = cls.from_bytes(chunk)
    except KeyError:
        # Add context information
        value = UnknownType.from_bytes(chunk)
    return value, remainder[length:]


@six.add_metaclass(Registry)
class Type(object):
    """
    The superclass for all supported types.
    """
    TYPECLASS = TypeInfo.UNIVERSAL
    TAG = 0
    value = None

    @classmethod
    def validate(cls, data):
        """
        Given a bytes object, checks if the given class *cls* supports decoding
        this object. If not, raises a ValueError.
        """
        # TODO: Making this function return a boolean instead of raising an exception would make the code potentially more readable.
        tinfo = TypeInfo.from_bytes(data[0])
        if tinfo.cls != cls.TYPECLASS or tinfo.tag != cls.TAG:
            raise ValueError('Invalid type header! '
                             'Expected a %s class with tag '
                             'ID 0x%02x, but got a %s class with '
                             'tag ID 0x%02x' % (
                                 cls.TYPECLASS, cls.TAG, tinfo.cls,
                                 six.byte2int(data)))

    @classmethod
    def from_bytes(cls, data):
        """
        Given a bytes object, this method reads the type information and length
        and uses it to convert the bytes representation into a python object.

        :raises puresnmp.x690.exc.InvalidValueLength: If the packet-length does
            not match the expected length reported in the package header.
        """

        if not data:
            return Null()
        cls.validate(data)
        expected_length, data = decode_length(data[1:])
        if len(data) != expected_length:
            raise InvalidValueLength(
                'Corrupt packet: Unexpected length for {0} Expected {1} '
                '(0x{1:02x}) but got {2} (0x{2:02x}). Consider increasing '
                'puresnmp.transport.BUFFER_SIZE.'.format(
                    cls, expected_length, len(data)))
        return cls.decode(data)

    @classmethod
    def decode(cls, data):  # pragma: no cover
        """
        This method takes a bytes object which contains the raw content octets
        of the object. That means, the octets *without* the type information
        and length.

        This function must be overridden by the concrete subclasses.
        """
        raise NotImplementedError(
            'Decoding is not yet implemented on %s' % cls)

    def __bytes__(self):  # pragma: no cover
        """
        Convert this instance into a bytes object. This must be implemented by
        subclasses.
        """
        raise NotImplementedError('Not yet implemented')

    def __repr__(self):
        # pylint: disable=no-member
        return '%s(%r)' % (self.__class__.__name__, self.value)

    def pythonize(self):
        """
        Convert this instance to an appropriate pure Python object.
        """
        # pylint: disable=no-member
        return self.value

    def pretty(self):  # pragma: no cover
        """
        Returns a readable representation (possibly multiline) of the value.

        By default this simply returns the string representation. But more
        complex values may override this.
        """
        return unicode(self)

    if six.PY2:  # pragma: no cover
        def __unicode__(self):
            return repr(self)

        def __str__(self):
            return self.__bytes__()


class UnknownType(Type):
    """
    A fallback type for anything not in X.690.

    Instances of this class contain the raw information as parsed from the
    bytes as the following attributes:

    * ``value``: The value without leading metadata (as bytes value)
    * ``tag``: The *unparsed* "tag". This is the type ID as defined in the
      reference document. See :py:class:`~puresnmp.x690.util.TypeInfo` for
      details.
    * ``typeinfo``: unused (derived from *tag* and only here for consistency
      with ``__repr__`` of this class).
    """

    value = b''

    def __init__(self, tag, value, typeinfo=None):
        self.value = value
        self.tag = tag
        self.length = len(value)
        self.typeinfo = TypeInfo.from_bytes(tag)

    def __bytes__(self):
        return to_bytes([self.tag]) + encode_length(self.length) + self.value

    def __repr__(self):
        return '%s(%r, %r, typeinfo=%r)' % (
            self.__class__.__name__, self.tag, self.value, self.typeinfo)

    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        return (type(self) == type(other) and
                self.value == other.value and
                self.tag == other.tag)

    @classmethod
    def from_bytes(cls, data):
        """
        Overrides typical conversion by removing type validation. As, by
        definition this class is used for unknown types, we cannot validate
        them.
        """
        if not data:
            return Null()
        tag = six.byte2int(data)
        expected_length, data = decode_length(data[1:])
        if len(data) != expected_length:
            raise ValueError('Corrupt packet: Unexpected length for {0} '
                             'Expected {1} (0x{1:02x}) '
                             'but got {2} (0x{2:02x})'.format(
                                 UnknownType, expected_length, len(data)))
        return UnknownType(tag, data)


class NonASN1Type(UnknownType):  # pragma: no cover
    def __init__(self, tag, value):
        warnings.warn('puresnmp.x690.types.NonASN1Type is deprecated,'
                      ' replace it with UnknownType', stacklevel=2)
        super(NonASN1Type, self).__init__(tag, value)


class Boolean(Type):
    TAG = 0x01
    value = False

    @staticmethod
    def decode(data):
        return Boolean(data != b'\x00')

    @classmethod
    def validate(cls, data):
        super(Boolean, cls).validate(data)
        if six.indexbytes(data, 1) != 1:
            raise ValueError('Unexpected Boolean value. Length should be 1,'
                             ' it was %d' % six.indexbytes(data, 1))

    def __init__(self, value):
        self.value = value

    def __bytes__(self):
        return to_bytes([1, 1, int(self.value)])

    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        return type(self) == type(other) and self.value == other.value


class Null(Type):
    TAG = 0x05

    def __init__(self):
        self.value = None

    @classmethod
    def validate(cls, data):
        super(Null, cls).validate(data)
        if six.indexbytes(data, 1) != 0:
            raise ValueError('Unexpected NULL value. Length should be 0, it '
                             'was %d' % six.indexbytes(data, 1))

    @classmethod
    def decode(cls, data):
        return Null()

    def __bytes__(self):
        return b'\x05\x00'

    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        return type(self) == type(other)

    def __repr__(self):
        return 'Null()'

    def __bool__(self):
        return False

    def __nonzero__(self):  # pragma: no cover (__bool__ for py2)
        return False


class OctetString(Type):
    TAG = 0x04
    value = b''

    @classmethod
    def decode(cls, data):
        return cls(data)

    def __init__(self, value):
        if isinstance(value, unicode):
            self.value = value.encode('ascii')
        else:
            self.value = value
        self.length = encode_length(len(self.value))

    def __bytes__(self):
        tinfo = TypeInfo(self.TYPECLASS, TypeInfo.PRIMITIVE, self.TAG)
        return to_bytes(tinfo) + self.length + self.value

    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        return type(self) == type(other) and self.value == other.value

    def pythonize(self):
        """
        Convert this object in an appropriate python object
        """
        return self.value


class Sequence(Type):
    """
    Represents an X.690 sequence type. Instances of this class are iterable and
    indexable.
    """
    TAG = 0x10
    value = []

    @classmethod
    def decode(cls, data):
        output = []
        while data:
            value, data = pop_tlv(data)
            output.append(value)
        return Sequence(*output)

    def __init__(self, *items):
        self.items = items

    def __bytes__(self):
        items = [to_bytes(item) for item in self]
        output = b''.join(items)
        length = encode_length(len(output))
        tinfo = TypeInfo(TypeInfo.UNIVERSAL, TypeInfo.CONSTRUCTED,
                         Sequence.TAG)
        return to_bytes(tinfo) + length + output

    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        return type(self) == type(other) and self.items == other.items

    def __repr__(self):
        item_repr = [repr(item) for item in self]
        return 'Sequence(%s)' % ', '.join(item_repr)

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        return iter(self.items)

    def __getitem__(self, idx):
        return self.items[idx]

    def pythonize(self):
        return [obj.pythonize() for obj in self]

    def pretty(self):  # pragma: no cover
        """
        Overrides :py:meth:`.Type.pretty`
        """
        lines = [self.__class__.__name__]
        for item in self.items:
            lines.append('   %s' % item.pretty())
        return '\n'.join(lines)


class Integer(Type):
    SIGNED = True
    TAG = 0x02
    value = 0

    @classmethod
    def decode(cls, data):
        return cls(int_from_bytes(data, 'big', signed=cls.SIGNED))

    def __init__(self, value):
        self.value = value

    def __bytes__(self):
        octets = [self.value & 0b11111111]

        # Append remaining octets for long integers.
        remainder = self.value
        while remainder not in (0, -1):
            remainder = remainder >> 8
            octets.append(remainder & 0b11111111)

        if remainder == 0 and octets[-1] == 0b10000000:
            octets.append(0)
        octets.reverse()

        # remove leading octet if there is a string of 9 zeros or ones
        while (len(octets) > 1 and
               ((octets[0] == 0 and octets[1] & 0b10000000 == 0) or
                (octets[0] == 0b11111111 and octets[1] & 0b10000000 != 0))):
            del octets[0]

        tinfo = TypeInfo(self.TYPECLASS, TypeInfo.PRIMITIVE, self.TAG)
        return to_bytes(tinfo) + to_bytes([len(octets)]) + to_bytes(octets)

    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        return type(self) == type(other) and self.value == other.value


class ObjectIdentifier(Type):
    """
    Represents an OID.

    Instances of this class support containment checks to determine if one OID
    is a sub-item of another::

        >>> ObjectIdentifier(1, 2, 3, 4, 5) in ObjectIdentifier(1, 2, 3)
        True

        >>> ObjectIdentifier(1, 2, 4, 5, 6) in ObjectIdentifier(1, 2, 3)
        False
    """
    TAG = 0x06
    value = b''

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
        """
        Inverse function of :py:meth:`~.ObjectIdentifier.decode_large_value`
        """
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
        # Special case for "empty" object identifiers which should be returned
        # as "0"
        if not data:
            return ObjectIdentifier(0)

        # unpack the first byte into first and second sub-identifiers.
        data0 = six.byte2int(data)
        first, second = data0 // 40, data0 % 40
        output = [first, second]

        remaining = six.iterbytes(data[1:])

        for char in remaining:
            # Each node can only contain values from 0-127. Other values need
            # to be combined.
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

        if not isinstance(value, six.string_types):
            raise TypeError('%r is not of type `str`' % value)

        if value == '.':
            return ObjectIdentifier(1)

        if isinstance(value, str) and value.startswith('.'):
            value = value[1:]

        identifiers = [int(ident, 10) for ident in value.split('.')]
        return ObjectIdentifier(*identifiers)

    def __init__(self, *identifiers):
        # pylint: disable=line-too-long

        # If the user hands in an iterable, instead of positional arguments,
        # make sure we unpack it
        if len(identifiers) == 1 and not isinstance(identifiers[0], int):
            identifiers = [int(ident) for ident in identifiers[0]]

        if len(identifiers) > 1:
            # The first two bytes are collapsed according to X.690
            # See https://en.wikipedia.org/wiki/X.690#BER_encoding
            first, second, rest = identifiers[0], identifiers[1], identifiers[2:]
            first_output = (40*first) + second
        else:
            first_output = identifiers[0]
            rest = tuple()

        # Values above 127 need a special encoding. They get split up into
        # multiple positions.
        exploded_high_values = []
        for char in rest:
            if char > 127:
                exploded_high_values.extend(
                    ObjectIdentifier.encode_large_value(char))
            else:
                exploded_high_values.append(char)

        self.identifiers = tuple(identifiers)
        collapsed_identifiers = [first_output]
        for subidentifier in rest:
            collapsed_identifiers.extend(
                ObjectIdentifier.encode_large_value(subidentifier))
        self.__collapsed_identifiers = tuple(collapsed_identifiers)
        self.length = encode_length(len(self.__collapsed_identifiers))

    def __int__(self):
        if len(self.identifiers) != 1:
            raise ValueError('Only ObjectIdentifier with one node can be '
                             'converted to int. %r is not convertable' % self)
        return self.identifiers[0]

    if six.PY2:  # pragma: no cover
        def __str__(self):
            output = to_bytes([self.TAG])
            if self.__collapsed_identifiers == (0,):
                output += b'\x00'
            else:
                output += self.length + to_bytes(self.__collapsed_identifiers)
            return output

        def __unicode__(self):
            return '.'.join([unicode(_) for _ in self.identifiers])
    else:
        def __str__(self):
            return '.'.join([unicode(_) for _ in self.identifiers])

        def __bytes__(self):
            output = to_bytes([self.TAG])
            if self.__collapsed_identifiers == (0,):
                output += b'\x00'
            else:
                output += self.length + to_bytes(self.__collapsed_identifiers)
            return output

    def __repr__(self):
        return 'ObjectIdentifier(%r)' % (self.identifiers, )

    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck, protected-access
        return (type(self) == type(other) and
                self.__collapsed_identifiers == other.__collapsed_identifiers)

    def __len__(self):
        return len(self.identifiers)

    def __contains__(self, other):
        """
        Check if one OID is a child of another.

        TODO: This has been written in the middle of the night! It's messy...
        """
        # pylint: disable=invalid-name

        a, b = other.identifiers, self.identifiers

        # if both have the same amount of identifiers, check for equality
        if len(a) == len(b):
            return a == b

        # if "self" is longer than "other", self cannot be "in" other
        if len(b) > len(a):
            return False

        # For all other cases:
        #   1. zero-fill
        #   2. drop identical items from the front (leaving us with "tail")
        #   3. compare both tails
        zipped = zip_longest(a, b, fillvalue=None)
        tail = []
        for tmp_a, tmp_b in zipped:
            if tmp_a == tmp_b and not tail:
                continue
            tail.append((tmp_a, tmp_b))

        # if we only have Nones in "b", we know that "a" was longer and that it
        # is a direct subtree of "b" (no diverging nodes). Otherwise we would
        # have te divergence in "b", and we can say that "b is contained in a"
        _, unzipped_b = zip(*tail)
        if all([x is None for x in unzipped_b]):
            return True

        # In all other cases we end up with an unmatching tail and know that "b
        # is not contained in a".
        return False

    def __lt__(self, other):
        return self.identifiers < other.identifiers

    def __hash__(self):
        return hash(self.identifiers)

    def __add__(self, other):
        nodes = self.identifiers + other.identifiers
        return ObjectIdentifier(*nodes)

    def __getitem__(self, index):
        return ObjectIdentifier(self.identifiers[index])

    def pythonize(self):
        return '.'.join([unicode(_) for _ in self.identifiers])

    def parentof(self, other):
        """
        Convenience method to check whether this OID is a parent of another OID
        """
        return other in self

    def childof(self, other):
        """
        Convenience method to check whether this OID is a child of another OID
        """
        return self in other


class ObjectDescriptor(Type):
    TAG = 0x07


class External(Type):
    TAG = 0x08


class Real(Type):
    TAG = 0x09
    value = 0.0


class Enumerated(Type):
    TAG = 0x0a


class EmbeddedPdv(Type):
    TAG = 0x0b


class Utf8String(Type):
    TAG = 0x0c
    value = ''


class RelativeOid(Type):
    TAG = 0x0d


class Set(Type):
    TAG = 0x11


class NumericString(Type):
    TAG = 0x12


class PrintableString(Type):
    TAG = 0x13
    value = ''


class T61String(Type):
    TAG = 0x14
    __INITIALISED = False

    def __init__(self, value):
        if not T61String.__INITIALISED:
            t61codec.register()
            self.__INITIALISED = True
        if isinstance(value, six.text_type):
            self.value = value.encode('t61')
        else:
            self.value = value
        self.length = encode_length(len(self.value))

    def __bytes__(self):
        tinfo = TypeInfo(self.TYPECLASS, TypeInfo.PRIMITIVE, self.TAG)
        return to_bytes(tinfo) + self.length + self.value

    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        return type(self) == type(other) and self.value == other.value

    @classmethod
    def decode(cls, data):
        return cls(data)

    def pythonize(self):
        """
        Convert this object in an appropriate python object
        """
        return self.value.decode('t61')


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


class EOC(Type):
    TAG = 0x00


class BitString(Type):
    TAG = 0x03
