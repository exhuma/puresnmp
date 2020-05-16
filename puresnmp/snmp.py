"""
This module contains data-types and helpers which are proper to the SNMP
protocol and independent of X.690
"""
from typing import (
    TYPE_CHECKING,
    Any,
    Iterable,
    Iterator,
    List,
    Tuple,
    Union,
    cast
)

import six

from .x690.types import (
    Integer,
    Null,
    ObjectIdentifier,
    Sequence,
    Type,
    pop_tlv
)

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


class VarBind(object):
    '''
    A "VarBind" is a 2-tuple containing an object-identifier and the
    corresponding value.
    '''

    # TODO: This class should be split in two for both the raw and pythonic
    #       API, that would simplify the typing of both "oid" and "value"a lot
    #       and keep things explicit
    oid = ObjectIdentifier(0)  # type: Union[str, ObjectIdentifier]
    value = None  # type: Union[PyType, Type[PyType]]

    def __init__(self, oid, value):
        # type: (Union[ObjectIdentifier, str], PyType) -> None
        if not isinstance(oid, (ObjectIdentifier,) + six.string_types):  # type: ignore
            raise TypeError('OIDs for VarBinds must be ObjectIdentifier or str'
                            ' instances! Your value: %r' % oid)
        if isinstance(oid, six.string_types):
            oid = ObjectIdentifier.from_string(oid)
        self.oid = oid
        self.value = value

    def __iter__(self):
        # type: () -> Iterator[Union[ObjectIdentifier, PyType]]
        return iter([self.oid, self.value])  # type: ignore

    def __getitem__(self, idx):
        return list(self)[idx]

    def __lt__(self, other):
        # type: (Any) -> bool
        return (self.oid, self.value) < (other.oid, other.value)

    def __eq__(self, other):
        # type: (Any) -> bool
        return (self.oid, self.value) == (other.oid, other.value)

    def __hash__(self):
        # type: () -> int
        return hash((self.oid, self.value))

    def __repr__(self):
        # type: () -> str
        return 'VarBind(%r, %r)' % (self.oid, self.value)
