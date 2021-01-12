import ipaddress
from typing import Callable, Union

from puresnmp.exc import SnmpError

TAnyIp = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
TTransportHandler = Callable[[TAnyIp, int, bytes], bytes]


def generate_engine_id_ip(pen: int, ip: TAnyIp) -> bytes:
    buffer = bytearray(pen.to_bytes(4, "big"))
    fmt = 1 if ip.version == 4 else 2
    buffer.append(fmt)
    buffer.extend(ip.packed)
    return bytes(buffer)


def generate_engine_id_mac(pen: int, mac_address: str) -> bytes:
    if "-" in mac_address:
        octets = [bytes.fromhex(oct) for oct in mac_address.split("-")]
    else:
        octets = [bytes.fromhex(oct) for oct in mac_address.split(":")]
    buffer = bytearray(pen.to_bytes(4, "big"))
    buffer.append(3)
    buffer.extend(octets)
    return bytes(buffer)


def generate_engine_id_text(pen: int, text: str) -> bytes:
    if len(text) > 27:
        raise SnmpError(
            "Invalid engine ID. Text must have fewer than 27 characters"
        )
    buffer = bytearray(pen.to_bytes(4, "big"))
    buffer[0] = 1
    buffer.append(4)
    buffer.extend(text.encode("ascii"))
    return bytes(buffer)


def generate_engine_id_octets(pen: int, octets: bytes) -> bytes:
    if len(octets) > 27:
        raise SnmpError(
            f"Invalid engine ID. The value {octets!r} is longer than 27 octets"
        )
    buffer = bytearray(pen.to_bytes(4, "big"))
    buffer.append(5)
    buffer.extend(octets)
    return bytes(buffer)