"""
Low-Level network transport.

This module mainly exist to enable a "seam" for mocking/patching out during
testing.

The module is excluded from coverage. It contains all the "dirty" stuff that's
hard to test.
"""

# TODO (beginner, no-dev): Ignore this file from coverage without adding "pragma: no cover" to each function.

import socket
import logging
from ipaddress import ip_address

from .exc import Timeout

LOG = logging.getLogger(__name__)
RETRIES = 3


def send(ip: str, port: int, packet: bytes, timeout: int=2) -> bytes:  # pragma: no cover
    """
    Opens a TCP connection to *ip:port*, sends a packet with *bytes* and returns
    the raw bytes as returned from the remote host.

    If the connection fails due to a timeout, the connection is retried 3 times.
    If it still failed, a Timeout exception is raised.
    """
    checked_ip = ip_address(ip)
    if checked_ip.version == 4:
        address_family = socket.AF_INET
    else:
        address_family = socket.AF_INET6

    sock = socket.socket(address_family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    sock.sendto(packet, (ip, port))
    for _ in range(RETRIES):
        try:
            response = sock.recv(4096)
            break
        except socket.timeout:
            LOG.error('Timeout')  # TODO add detail
            continue
    else:
        raise Timeout("Max of %d retries reached" % RETRIES)
    sock.close()
    return response


def get_request_id():  # pragma: no cover
    """
    Generates a SNMP request ID. This value should be unique for each request.
    """
    from time import time
    return int(time())  # TODO check if this is good enough. My gut tells me "no"! Depends if it has to be unique across all clients, or just one client. If it's just one client it *may* be enough.
