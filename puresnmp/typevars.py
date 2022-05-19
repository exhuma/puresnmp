"""
This module contains variour type aliases for type checking
"""
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import TypeVar, Union

#: This is a type variable helps to properly hint functions which take in a
#: "puresnmp" type and return a pythonic type
TWrappedPyType = TypeVar("TWrappedPyType")

TAnyIp = Union[IPv4Address, IPv6Address]


@dataclass(frozen=True)
class SocketInfo:
    """
    A simple tuple containing an IP address and port number
    """

    address: str
    port: int

    def __str__(self) -> str:
        return f"{self.address}:{self.port}"


@dataclass(frozen=True)
class SocketResponse:
    """
    Metadata for socket responses
    """

    data: bytes
    info: SocketInfo
