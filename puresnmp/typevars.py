"""
This module contains variour type aliases for type checking
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TypeVar, Union

#: This is a type variable helps to properly hint functions which take in a
#: "puresnmp" type and return a pythonic type
TWrappedPyType = TypeVar("TWrappedPyType")


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
