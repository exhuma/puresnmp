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

from .exc import Timeout
from .x690.util import visible_octets

LOG = logging.getLogger(__name__)
RETRIES = 3


def recv_all(sock):
    '''
    Read data from socket using ``sock.recv`` until no bytes are left to read.

    Unfortunately, decoding the byte-length is non-trivial according to the
    X690 standard (see :py:func:`puresnmp.x690.types.pop_tlv` and
    :py:func:`puresnmp.x690.util.decode_length` for more details.

    This means a simple call to ``recv`` does not have length-information and
    detecting the end of the stream is more error-prone.

    This could be refactored in the future to meld the x690 and "transport"
    layers together.

    See https://stackoverflow.com/a/17697651/160665
    '''
    buffer_size = 4096 # 4 KiB
    chunks = []
    while True:
        chunk = sock.recv(buffer_size)
        chunks.append(chunk)
        if len(chunk) < buffer_size:
            # either 0 or end of data
            break
    data = b''.join(chunks)
    return data


def send(ip, port, packet, timeout=2):  # pragma: no cover
    # type: ( str, int, bytes, int ) -> bytes
    """
    Opens a TCP connection to *ip:port*, sends a packet with *bytes* and
    returns the raw bytes as returned from the remote host.

    If the connection fails due to a timeout, the connection is retried 3
    times.  If it still failed, a Timeout exception is raised.
    """
    checked_ip = ip_address(ip)
    if checked_ip.version == 4:
        address_family = socket.AF_INET
    else:
        address_family = socket.AF_INET6

    sock = socket.socket(address_family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    for num_retry in range(RETRIES):
        try:
            if LOG.isEnabledFor(logging.DEBUG):
                hexdump = visible_octets(packet)
                LOG.debug('Sending packet to %s:%s (attempt %d/%d)\n%s',
                          ip, port, (num_retry+1), RETRIES, hexdump)
            sock.sendto(packet, (ip, port))
            response = recv_all(sock)
            break
        except socket.timeout:
            LOG.debug('Timeout during attempt #%d',
                      (num_retry+1))  # TODO add detail
            continue
    else:
        raise Timeout("Max of %d retries reached" % RETRIES)
    sock.close()

    if LOG.isEnabledFor(logging.DEBUG):
        hexdump = visible_octets(response)
        LOG.debug('Received packet:\n%s', hexdump)

    return response


def get_request_id():  # pragma: no cover
    """
    Generates a SNMP request ID. This value should be unique for each request.
    """
    # TODO check if this is good enough. My gut tells me "no"! Depends if it
    # has to be unique across all clients, or just one client. If it's just
    # one client it *may* be enough.
    from time import time
    return int(time())
