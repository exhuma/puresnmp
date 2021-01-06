"""
This module contains variour type aliases for type checking
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import TypeVar, Union

#: This type represents the data type of an SNMP value in the Python worldj.
PyType = Union[str, bytes, int, datetime, timedelta, None, float]


#: This is a type variable helps to properly hint functions which take in a
#: "puresnmp" type and return a pythonic type
TWrappedPyType = TypeVar("TWrappedPyType", bound=PyType)

TAnyIp = Union[IPv4Address, IPv6Address]


@dataclass
class SocketInfo:
    """
    A simple tuple containing an IP address and port number
    """

    address: str
    port: int


@dataclass
class SocketResponse:
    """
    Metadata for socket responses
    """

    data: bytes
    info: SocketInfo
