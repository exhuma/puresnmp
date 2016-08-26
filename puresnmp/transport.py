"""
Low-Level network transport.

This module mainly exist to enable a "seam" for mocking/patching out during
testing.

The module is excluded from coverage. It contains all the "dirty" stuff that's hard to test.
"""

# TODO (beginner, no-dev): Ignore this file from coverage without adding "pragma: no cover" to each function.

import socket
import logging
from ipaddress import ip_address

from .exc import Timeout

LOG = logging.getLogger(__name__)
RETRIES = 3


def send(ip: str, port: int, packet: bytes) -> bytes:  # pragma: no cover
    checked_ip = ip_address(ip)
    address_family = socket.AF_INET if checked_ip.version == 4 else socket.AF_INET6
    sock = socket.socket(address_family, socket.SOCK_DGRAM)

    sock.sendto(packet, (ip, port))
    for x in range(RETRIES):
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
    from time import time
    return int(time())  # TODO check if this is good enough. My gut tells me "no"!
