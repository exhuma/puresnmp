"""
This module contains variour type aliases for type checking
"""
from datetime import datetime, timedelta
from typing import NamedTuple, TypeVar, Union

#: This type represents the data type of an SNMP value in the Python worldj.
PyType = Union[str, bytes, int, datetime, timedelta, None, float]


#: This is a type variable helps to properly hint functions which take in a
#: "puresnmp" type and return a pythonic type
TWrappedPyType = TypeVar('TWrappedPyType', bound=PyType)


class SocketInfo(NamedTuple):
    address: str
    port: int
class SocketResponse(NamedTuple):
    data: bytes
    info: SocketInfo
