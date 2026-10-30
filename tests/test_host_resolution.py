"""
Tests for host name resolution in :py:class:`puresnmp.api.raw.Client`.
"""

import asyncio
import logging
import socket
from ipaddress import IPv4Address, IPv6Address
from typing import Any, List, Tuple
from unittest.mock import patch

import pytest

from puresnmp import V2C, Client
from puresnmp.transport import Endpoint, send_udp


def _result(family: int, address: str, port: int = 161) -> Any:
    sockaddr: Tuple[Any, ...] = (address, port)
    if family == socket.AF_INET6:
        sockaddr = (address, port, 0, 0)
    return (family, socket.SOCK_DGRAM, 17, "", sockaddr)


def _client(host: str, port: int = 161) -> Client:
    return Client(host, V2C("public"), port=port)


def _find_endpoint(client: Client) -> Endpoint:
    for cell in client.transport_handler.__closure__ or ():  # type: ignore
        if isinstance(cell.cell_contents, Endpoint):
            return cell.cell_contents
    raise AssertionError("no endpoint")  # pragma: no cover


def test_ipv6_only_name_resolves_to_ipv6() -> None:
    """
    Ensure a name with only an IPv6 address yields an IPv6Address.
    """
    with patch(
        "socket.getaddrinfo",
        return_value=[_result(socket.AF_INET6, "2001:db8::1")],
    ) as mocked:
        client = _client("v6.example.com", port=1161)
    mocked.assert_called_once_with(
        "v6.example.com", 1161, type=socket.SOCK_DGRAM
    )
    assert _find_endpoint(client) == Endpoint(IPv6Address("2001:db8::1"), 1161)


def test_ipv4_name_resolves_to_ipv4() -> None:
    """
    Ensure a name with an IPv4 address still yields an IPv4Address.
    """
    with patch(
        "socket.getaddrinfo",
        return_value=[_result(socket.AF_INET, "192.0.2.7")],
    ):
        client = _client("v4.example.com")
    assert _find_endpoint(client) == Endpoint(IPv4Address("192.0.2.7"), 161)


def test_ipv4_preferred_over_earlier_ipv6() -> None:
    """
    Ensure an IPv4 address is used for dual-stack names, even if the
    resolver lists an IPv6 address first (as for "localhost").
    """
    results: List[Any] = [
        _result(socket.AF_INET6, "2001:db8::2"),
        _result(socket.AF_INET, "192.0.2.8"),
    ]
    with patch("socket.getaddrinfo", return_value=results):
        client = _client("both.example.com")
    assert _find_endpoint(client).ip == IPv4Address("192.0.2.8")


@pytest.mark.parametrize("literal", ["192.0.2.1", "2001:db8::1", "::1"])
def test_ip_literal_is_not_resolved(literal: str) -> None:
    """
    Ensure IP literals do not trigger a name resolution.
    """
    with patch("socket.getaddrinfo") as mocked:
        client = _client(literal)
    mocked.assert_not_called()
    assert str(_find_endpoint(client).ip) == literal


def test_resolution_failure_raises_gaierror() -> None:
    """
    Ensure an unresolvable name raises socket.gaierror as before.
    """
    with patch(
        "socket.getaddrinfo", side_effect=socket.gaierror(-2, "Name unknown")
    ):
        with pytest.raises(socket.gaierror):
            _client("nope.invalid")


def _ipv6_loopback_available() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("::1", 0))
    except OSError:  # pragma: no cover
        return False
    return True


@pytest.mark.skipif(
    not _ipv6_loopback_available(), reason="IPv6 loopback not available"
)
def test_send_udp_over_ipv6_loopback() -> None:
    """
    Ensure the UDP transport talks to an IPv6 agent.
    """

    async def scenario() -> bytes:
        loop = asyncio.get_running_loop()

        class Agent(asyncio.DatagramProtocol):
            def connection_made(self, transport: Any) -> None:
                self.transport = transport

            def datagram_received(self, data: bytes, addr: Any) -> None:
                self.transport.sendto(b"re:" + data, addr)

        transport, _ = await loop.create_datagram_endpoint(
            Agent, local_addr=("::1", 0)
        )
        port = transport.get_extra_info("sockname")[1]
        try:
            return await send_udp(Endpoint(IPv6Address("::1"), port), b"ping")
        finally:
            transport.close()

    assert asyncio.run(scenario()) == b"re:ping"


def test_resolution_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    """
    Ensure the resolved address is logged at DEBUG.
    """
    with (
        caplog.at_level(logging.DEBUG, logger="puresnmp.transport"),
        patch(
            "socket.getaddrinfo",
            return_value=[_result(socket.AF_INET6, "2001:db8::1")],
        ),
    ):
        _client("v6.example.com")
    records = [r for r in caplog.records if r.name == "puresnmp.transport"]
    assert len(records) == 1
    assert records[0].levelno == logging.DEBUG
    assert records[0].getMessage() == "Resolved v6.example.com to 2001:db8::1"
