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

from .exc import Timeout
from .x690.util import visible_octets
from .transport import get_request_id

LOG = logging.getLogger(__name__)


class SNMPClientProtocol:
    def __init__(self, packet, loop):
        self.packet = packet
        self.transport = None
        self.loop = loop
        self.future = loop.create_future()

    def connection_made(self, transport):
        self.transport = transport
    
        if LOG.isEnabledFor(logging.DEBUG):
            hexdump = visible_octets(self.packet)
            ip, port = self.transport.get_extra_info('peername', ('', ''))
            LOG.debug('Sending packet to %s:%s\n%s', ip, port, hexdump)

        self.transport.sendto(self.packet)

    def connection_lost(self, exc):
        if LOG.isEnabledFor(logging.DEBUG):
            if exc is None:
                LOG.debug('Socket closed')
            else:
                LOG.debug('Connection lost', exc)

        if exc is not None:
            self.future.set_exception(exc)

    def datagram_received(self, data, addr):
        if LOG.isEnabledFor(logging.DEBUG):
            hexdump = visible_octets(data)
            LOG.debug('Received packet:\n%s', hexdump)

        self.future.set_result(data)
        self.transport.close()

    def error_received(self, exc):
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug('Error received', exc)

        self.future.set_exception(exc)

    async def get_data(self, timeout):
        try:
            return await asyncio.wait_for(self.future, timeout, loop=self.loop)
        except asyncio.TimeoutError:
            self.transport.abort()
            raise Timeout("{} second timeout exceeded".format(timeout))


async def send(ip, port, packet, timeout=6, loop=None):  # pragma: no cover
    # type: ( str, int, bytes, int ) -> bytes
    """
    Opens a UDP socket to *ip:port*, sends a packet with *bytes* and
    returns the raw bytes as returned from the remote host.

    If the connection fails due to a timeout, a Timeout exception is raised.
    """
    if loop is None:
        loop = asyncio.get_event_loop()

    # family could be specified here (and is in the sync implementation), is it needed?
    # are retries necessary for async implementation?
    transport, protocol = await loop.create_datagram_endpoint(
                            lambda: SNMPClientProtocol(packet, loop),
                            remote_addr=(ip, port)
                        )

    response = await protocol.get_data(timeout)

    return response

