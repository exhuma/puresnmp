"""
Low-Level network transport for asyncio.

This module mainly exist to enable a "seam" for mocking/patching out during
testing.

The module is excluded from coverage. It contains all the "dirty" stuff that's
hard to test.
"""

# TODO (beginner, no-dev): Ignore this file from coverage without adding
#                          "pragma: no cover" to each function.

import asyncio
import logging
from asyncio.events import AbstractEventLoop
from typing import Optional, Tuple, Union

from ..exc import Timeout
from ..transport import Transport as SyncTransport
from ..x690.util import visible_octets

LOG = logging.getLogger(__name__)


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
            ip, port = self.transport.get_extra_info('peername', ('', ''))
            LOG.debug('Sending packet to %s:%s\n%s', ip, port, hexdump)

        self.transport.sendto(self.packet)

    def connection_lost(self, exc):
        # type: (Optional[Exception]) -> None
        """
        Handles the socket being closed optionally passing on an exception.
        """
        if LOG.isEnabledFor(logging.DEBUG):
            if exc is None:
                LOG.debug('Socket closed')
            else:
                LOG.debug('Connection lost: %s', exc)

        if exc is not None:
            self.future.set_exception(exc)

    def datagram_received(self, data, addr):
        # type: (Union[bytes, str], Tuple[str, int]) -> None
        """
        Receive the data and close the connection.
        """
        if LOG.isEnabledFor(logging.DEBUG) and isinstance(data, bytes):
            hexdump = visible_octets(data)
            LOG.debug('Received packet:\n%s', hexdump)

        self.future.set_result(data)
        if self.transport:
            self.transport.close()

    def error_received(self, exc):
        # type: (Exception) -> None
        """
        Pass the exception along if there is an error.
        """
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug('Error received: %s', exc)

        self.future.set_exception(exc)

    async def get_data(self, timeout):
        # type: (int) -> bytes
        """
        Retrieve the response data back into the calling coroutine.
        """
        try:
            return await asyncio.wait_for(self.future, timeout, loop=self.loop)
        except asyncio.TimeoutError:
            if self.transport:
                self.transport.abort()
            raise Timeout("{} second timeout exceeded".format(timeout))


class Transport(SyncTransport):

    async def send(  # type: ignore
            self, ip, port, packet, timeout=6, loop=None):  # pragma: no cover
        # type: ( str, int, bytes, int, Optional[AbstractEventLoop] ) -> bytes
        """
        A coroutine that opens a UDP socket to *ip:port*, sends a packet with
        *bytes* and returns the raw bytes as returned from the remote host.

        If the connection fails due to a timeout, a Timeout exception is
        raised.
        """
        if loop is None:
            loop = asyncio.get_event_loop()

        # family could be specified here (and is in the sync implementation),
        # is it needed? are retries necessary for async implementation?
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SNMPClientProtocol(packet, loop),  # type: ignore
            remote_addr=(ip, port)
        )

        response = await protocol.get_data(timeout)  # type: ignore

        return response  # type: ignore
