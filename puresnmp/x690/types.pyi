from datetime import datetime
from sys import version_info
from typing import Any, Dict, Generic, Iterator, List, Optional, Tuple
from typing import Type as TypeType
from typing import TypeVar, Union

from puresnmp.x690.util import TypeInfo

TPythonType = TypeVar('TPythonType')


if version_info[0] == 3:
    unicode = str


class Registry(type):
    __registry:  Dict[Tuple[str, int], TypeType[Type[Any]]]
    def __new__(cls, name: str, parents: Tuple[type],
                dict_: Dict[str, Any]) -> 'Registry': ...

    @staticmethod
    def get(typeclass: str, typeid: int) -> TypeType[Type[Any]]: ...


def pop_tlv(data: bytes) -> Tuple[Type[Any], bytes]: ...


# Type --------

class Type(Generic[TPythonType]):
    value: Optional[TPythonType] = None
    @classmethod
    def validate(cls, data: bytes) -> None: ...

    @classmethod
    def from_bytes(cls, data: bytes) -> Type[TPythonType]: ...

    @classmethod
    def decode(cls, data: bytes) -> Type[TPythonType]: ...

    def __bytes__(self) -> bytes: ...
    def __repr__(self) -> str: ...
    def pythonize(self) -> Any: ...
    def pretty(self) -> str: ...

    if version_info[0] == 2:
        def __unicode__(self) -> unicode: ...
        def __str__(self) -> str: ...


class UnknownType(Type[bytes]):
    value = b''

    def __init__(self, tag: int, value: bytes,
                 typeinfo: Optional[TypeInfo] = None) -> None: ...

    @classmethod
    def from_bytes(cls, data: bytes) -> Union[Null, UnknownType]: ...


class NonASN1Type(UnknownType):
    def __init__(self, tag: int, value: Any) -> None: ...


class Boolean(Type[bool]):
    ...


class Null(Type[None]):
    ...


class OctetString(Type[bytes]):
    def __init__(self, value: Union[unicode, bytes]) -> None: ...


class Sequence(Type[List[Type[Any]]]):
    def __init__(self, *items: Type[Any]) -> None: ...


class Integer(Type[int]):
    def __init__(self, value: int) -> None: ...


class ObjectIdentifier(Type[str]):
    def __init__(self, *identifiers: int) -> None: ...
    def __contains__(self, other: 'ObjectIdentifier') -> bool: ...

    @staticmethod
    def decode_large_value(
        current_char: int, stream: Iterator[int]) -> int: ...

    @staticmethod
    def encode_large_value(value: int) -> List[int]: ...
    @staticmethod
    def from_string(value: str) -> 'ObjectIdentifier': ...
    def pythonize(self) -> str: ...
    def parentof(self, other: 'ObjectIdentifier') -> bool: ...
    def childof(self, other: 'ObjectIdentifier') -> bool: ...


class ObjectDescriptor(Type[str]):
    ...


class External(Type[bytes]):
    ...


class Real(Type[float]):
    ...


class Enumerated(Type[List[Any]]):
    ...


class EmbeddedPdv(Type[bytes]):
    ...


class Utf8String(Type[str]):
    ...


class RelativeOid(Type[str]):
    ...


class Set(Type[bytes]):
    ...


class NumericString(Type[str]):
    ...


class PrintableString(Type[str]):
    ...


class T61String(Type[str]):
    ...


class VideotexString(Type[str]):
    ...


class IA5String(Type[str]):
    ...


class UtcTime(Type[datetime]):
    ...


class GeneralizedTime(Type[datetime]):
    ...


class GraphicString(Type[str]):
    ...


class VisibleString(Type[str]):
    ...


class GeneralString(Type[str]):
    ...


class UniversalString(Type[str]):
    ...


class CharacterString(Type[str]):
    ...


class BmpString(Type[str]):
    ...


class EOC(Type[bytes]):
    ...


class BitString(Type[str]):
    ...
