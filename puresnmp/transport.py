"""
Low-Level network transport for asyncio.

This module mainly exist to enable a "seam" for mocking/patching out during
testing.

The module is excluded from coverage. It contains all the "dirty" stuff that's
hard to test.
"""

import asyncio
import logging
from asyncio.events import AbstractEventLoop
from asyncio.transports import BaseTransport
from typing import Any, Callable, NamedTuple, Optional, Tuple, Union

from typing_extensions import Protocol
from x690.util import visible_octets

from .exc import Timeout
from .typevars import SocketInfo, SocketResponse, TAnyIp

LOG = logging.getLogger(__name__)
MESSAGE_MAX_SIZE = 65507


class Endpoint(NamedTuple):
    """
    A tuple representing an UDP endpoint where a connection should be made to.
    """

    ip: TAnyIp
    port: int


class TSender(Protocol):
    """
    A typing-protocol for callables which send data out to the network
    """

    # pylint: disable=too-few-public-methods

    async def __call__(
        self,
        endpoint: Endpoint,
        packet: bytes,
        timeout: int = 6,
        loop: Optional[AbstractEventLoop] = None,
    ) -> bytes:
        ...


class SNMPTrapReceiverProtocol(asyncio.DatagramProtocol):
    """
    A protocol to handle incoming SNMP traps.

    The protocol requires a callable which is called with a
    :py:class:`~.SocketResponse` instance whenever a trap is received.
    """

    def __init__(self, callback: Callable[[SocketResponse], Any]) -> None:
        super().__init__()
        self.callback = callback
        self.transport: Optional[BaseTransport] = None

    def connection_made(self, transport: BaseTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        if LOG.isEnabledFor(logging.DEBUG):
            hexdump = visible_octets(data)
            LOG.debug("Received packet:\n%s", hexdump)
        self.callback(SocketResponse(data, SocketInfo(addr[0], addr[1])))


class SNMPClientProtocol(asyncio.DatagramProtocol):
    """
    An SNMP Client Protocol suitable for use with create_datagram_endpoint()
    that provide a method to convert the callback based API into a coroutine
    based API.

    """

    def __init__(self, packet, loop):
        # type: (bytes, AbstractEventLoop) -> None
        self.packet = packet
        self.transport = None  # type: Optional[asyncio.DatagramTransport]
        self.loop = loop
        self.future = loop.create_future()

    def connection_made(self, transport):  # type: ignore
        # type: (asyncio.DatagramTransport) -> None
        """
        Sends the SNMP request packet when a connection is made.
        """
        self.transport = transport

        if LOG.isEnabledFor(logging.DEBUG):
            hexdump = visible_octets(self.packet)
            ip, port = self.transport.get_extra_info("peername", ("", ""))
            LOG.debug("Sending packet to %s:%s\n%s", ip, port, hexdump)

        self.transport.sendto(self.packet)

    def connection_lost(self, exc):
        # type: (Optional[Exception]) -> None
        """
        Handles the socket being closed optionally passing on an exception.
        """
        if LOG.isEnabledFor(logging.DEBUG):
            if exc is None:
                LOG.debug("Socket closed")
            else:
                LOG.debug("Connection lost: %s", exc)

        if exc is not None:
            self.future.set_exception(exc)

    def datagram_received(self, data, addr):
        # type: (Union[bytes, str], Tuple[str, int]) -> None
        """
        Receive the data and close the connection.
        """
        if LOG.isEnabledFor(logging.DEBUG) and isinstance(data, bytes):
            hexdump = visible_octets(data)
            LOG.debug("Received packet:\n%s", hexdump)

        self.future.set_result(data)
        if self.transport:
            self.transport.close()

    def error_received(self, exc):
        # type: (Exception) -> None
        """
        Pass the exception along if there is an error.
        """
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("Error received: %s", exc)

        self.future.set_exception(exc)

    async def get_data(self, timeout):
        # type: (int) -> bytes
        """
        Retrieve the response data back into the calling coroutine.
        """
        try:
            return await asyncio.wait_for(self.future, timeout, loop=self.loop)
        except asyncio.TimeoutError as exc:
            if self.transport:
                self.transport.abort()
            raise Timeout(f"{timeout} second timeout exceeded") from exc


async def send(
    endpoint: Endpoint,
    packet: bytes,
    timeout: int = 6,
    loop: Optional[AbstractEventLoop] = None,
) -> bytes:  # pragma: no cover
    # pylint: disable=arguments-differ
    """
    A coroutine that opens a UDP socket to *ip:port*, sends a packet with
    *bytes* and returns the raw bytes as returned from the remote host.

    If the connection fails due to a timeout, a Timeout exception is
    raised.
    """
    if loop is None:
        loop = asyncio.get_event_loop()

    _, protocol = await loop.create_datagram_endpoint(
        lambda: SNMPClientProtocol(packet, loop),  # type: ignore
        remote_addr=(str(endpoint.ip), endpoint.port),
    )

    response = await protocol.get_data(timeout)  # type: ignore

    return response  # type: ignore


def default_trap_handler(info: SocketResponse) -> None:
    """
    A no-op implementation for trap handlers which only logs traps.
    """
    LOG.debug("Trap Received: %r", info)


async def listen(
    bind_address: str = "0.0.0.0",
    port: int = 162,
    callback: Callable[[SocketResponse], Any] = default_trap_handler,
    loop: Optional[AbstractEventLoop] = None,
) -> None:  # pragma: no cover
    """
    Sets up a listening UDP socket and returns a generator over recevied
    packets::

        >>> transport = Transport()  # doctest: +SKIP
        >>> for seq, packet in enumerate(transport.listen()):  # doctest: +SKIP
        ...     print(seq, repr(packet))
        0, b'...'
        1, b'...'
        2, b'...'

    .. note::

        This defaults to the standard SNMP Trap port 162. This is a
        privileged port so processes using this port must run as root!
    """
    if loop is None:
        loop = asyncio.get_event_loop()
    await loop.create_datagram_endpoint(
        lambda: SNMPTrapReceiverProtocol(callback),
        local_addr=(bind_address, port),
    )
