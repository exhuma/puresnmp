"""
Low-Level network transport.

This module mainly exist to enable a "seam" for mocking/patching out during
testing.

The module is excluded from coverage. It contains all the "dirty" stuff that's
hard to test.
"""

# TODO (beginner, no-dev): Ignore this file from coverage without adding
#                          "pragma: no cover" to each function.

import logging
import socket
from ipaddress import ip_address
from typing import TYPE_CHECKING, Generator

from .exc import Timeout
from .typevars import SocketInfo, SocketResponse
from .x690.util import visible_octets

LOG = logging.getLogger(__name__)

#: The default number of retries for UDP packets
RETRIES = 3

#: Low-level socket buffer-size. If you run into timeouts you may want to
#: increase this
BUFFER_SIZE = 4096  # 4 KiB


if TYPE_CHECKING:
    from typing import Optional


class Transport(object):
    """
    A simple UDP transport.

    Calling ``send`` will attempt to send a packet as many times as specified
    in *retries* (default=3). If it fails after those attemps, a
    py:exc:`puresnmp.Timeout` exception is raised.

    :param timeout: How long to wait on the socket before retrying
    :param retries: The number of retries attempted if a low-level
        socket-timeout occurs. If set to ``None`` it will use
        :py:data:`puresnmp.transport.RETRIES` as default.
    :param buffer_size: How much data to read from the socket. If this is too
        small, it may result in incomplete (corrupt) packages. This should be
        kept as low as possible (see ``man(2) recv``). If set to ``None`` it
        will use :py:data:`puresnmp.transport.BUFFER_SIZE` as default.
    """

    def __init__(self, timeout=2, retries=None, buffer_size=None):
        # type: (int, Optional[int], Optional[int]) -> None
        self.timeout = timeout
        self.retries = retries or RETRIES
        self.buffer_size = buffer_size or BUFFER_SIZE

    def send(
            self, ip, port, packet):  # pragma: no cover
        # type: ( str, int, bytes ) -> bytes
        """
        Opens a TCP connection to *ip:port*, sends a packet with *bytes* and
        returns the raw bytes as returned from the remote host.
        """
        checked_ip = ip_address(ip)
        if checked_ip.version == 4:
            address_family = socket.AF_INET
        else:
            address_family = socket.AF_INET6

        sock = socket.socket(address_family, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        for num_retry in range(self.retries):
            try:
                if LOG.isEnabledFor(logging.DEBUG):
                    hexdump = visible_octets(packet)
                    LOG.debug('Sending packet to %s:%s (attempt %d/%d)\n%s',
                              ip, port, (num_retry+1), self.retries, hexdump)
                sock.sendto(packet, (ip, port))
                response = sock.recv(self.buffer_size)
                break
            except socket.timeout:
                LOG.debug('Timeout during attempt #%d',
                          (num_retry+1))  # TODO add detail
                continue
        else:
            sock.close()
            raise Timeout(
                "Max of %d retries reached" % self.retries)  # type: ignore
        sock.close()

        if LOG.isEnabledFor(logging.DEBUG):
            hexdump = visible_octets(response)
            LOG.debug('Received packet:\n%s', hexdump)

        return response

    def listen(self, bind_address='0.0.0.0', port=162):  # pragma: no cover
        # type: (str, int) -> Generator[SocketResponse, None, None]
        """
        Sets up a listening UDP socket and returns a generator over recevied
        packets::

            >>> transport = Transport()
            >>> for seq, packet in enumerate(transport.listen()):
            ...     print(seq, repr(packet))
            0, b'...'
            1, b'...'
            2, b'...'

        .. note::

            This defaults to the standard SNMP Trap port 162. This is a
            privileged port so processes using this port must run as root!
        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((bind_address, port))
            while True:
                request, addr = sock.recvfrom(self.buffer_size)
                if LOG.isEnabledFor(logging.DEBUG):
                    hexdump = visible_octets(request)
                    LOG.debug('Received packet:\n%s', hexdump)

                yield SocketResponse(request, SocketInfo(addr[0], addr[1]))

    def get_request_id(self):  # pragma: no cover
        # type: () -> int
        """
        Generates a SNMP request ID. This value should be unique for each
        request.
        """
        # TODO check if this is good enough. My gut tells me "no"! Depends if
        # it has to be unique across all clients, or just one client. If it's
        # just one client it *may* be enough.
        from time import time
        return int(time())
