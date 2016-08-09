import socket


class SnmpError(Exception):
    pass


class Timeout(socket.timeout):
    pass
