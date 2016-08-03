"""
Low-Level network transport.

This module mainly exist to enable a "seam" for mocking/patching out during
testing.
"""
import socket


def send(ip: str, port: int, packet: bytes) -> bytes:
    sock = socket.socket(socket.AF_INET6,  # Internet
                         socket.SOCK_DGRAM)  # UDP

    sock.sendto(packet, (ip, port))
    response = sock.recv(4096)
    sock.close()
    return response


def get_request_id():
    from time import time
    return int(time())  # TODO check if this is good enough. My gut tells me "no"!
