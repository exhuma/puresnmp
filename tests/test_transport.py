import asyncio
import logging
import socket
from typing import Any, no_type_check
from unittest.mock import Mock

import pytest

import puresnmp.transport as tpt
from puresnmp.exc import Timeout
from puresnmp.typevars import SocketInfo, SocketResponse


def test_trap_protocol_receiving() -> None:
    """
    Ensure that receiving a trap is properly calling the callback
    """

    fake_container = {}

    def callback(response):  # type: ignore
        fake_container["payload"] = response.data
        fake_container["info"] = response.info

    proto = tpt.SNMPTrapReceiverProtocol(callback)
    proto.datagram_received(b"trap-packet", ("192.0.2.1", 42))

    expected = {
        "payload": b"trap-packet",
        "info": SocketInfo("192.0.2.1", 42),
    }

    assert fake_container == expected


@no_type_check
def test_trap_protocol_receiving_log(caplog) -> None:
    """
    Ensure that receiving a trap is logged
    """

    proto = tpt.SNMPTrapReceiverProtocol(lambda _: None)
    with caplog.at_level(logging.DEBUG):
        proto.datagram_received(b"trap-packet", ("192.0.2.1", 42))
    assert "Received packet" in caplog.text
    assert "74 72 61" in caplog.text, "hexdump of trap-packet not found"


@no_type_check
def test_trap_connection_handle() -> None:
    """
    Ensure the trap protocol transport is kept
    """
    proto = tpt.SNMPTrapReceiverProtocol(lambda: None)
    proto.connection_made("fake-transport")
    assert proto.transport == "fake-transport"


@pytest.mark.asyncio
async def test_client_proto_connection_made() -> None:
    """
    Ensure the queud UDP packet is sent on connection
    """
    mock_transport = Mock()
    proto = tpt.SNMPClientProtocol(b"SNMP-packet")
    proto.connection_made(mock_transport)
    mock_transport.sendto.assert_called_with(b"SNMP-packet")


@pytest.mark.asyncio
async def test_client_proto_connection_made_logging(caplog: Any) -> None:
    """
    Ensure we log established connections
    """
    mock_transport = Mock()
    mock_transport.get_extra_info.return_value = ("192.0.2.1", 42)
    proto = tpt.SNMPClientProtocol(b"SNMP-packet")
    with caplog.at_level(logging.DEBUG):
        proto.connection_made(mock_transport)
    assert "192.0.2.1:42" in caplog.text
    assert "53 4e 4d" in caplog.text, "hex-dump of packet not found in logs"


@pytest.mark.asyncio
async def test_client_proto_connection_lost() -> None:
    """
    Ensure we propagate exceptions when losing a connection
    """
    mock_transport = Mock()
    mock_transport.get_extra_info.return_value = ("192.0.2.1", 42)
    proto = tpt.SNMPClientProtocol(b"SNMP-packet")
    proto.connection_lost(ValueError("Hello World"))
    with pytest.raises(ValueError) as exc:
        proto.future.result()
    assert exc.match("Hello World")


@pytest.mark.asyncio
async def test_client_proto_connection_lost_log(caplog: Any) -> None:
    """
    Ensure we log exceptions on lost connections
    """
    mock_transport = Mock()
    mock_transport.get_extra_info.return_value = ("192.0.2.1", 42)
    proto = tpt.SNMPClientProtocol(b"SNMP-packet")
    with caplog.at_level(logging.DEBUG):
        proto.connection_lost(ValueError("Hello World"))
    assert "connection lost" in caplog.text.lower()
    assert "Hello World" in caplog.text


@pytest.mark.asyncio
async def test_client_proto_connection_close_log(caplog: Any) -> None:
    """
    Ensure we log "normal" connection closures
    """
    proto = tpt.SNMPClientProtocol(b"SNMP-packet")
    with caplog.at_level(logging.DEBUG):
        proto.connection_lost(None)
    assert "closed" in caplog.text.lower()


@pytest.mark.asyncio
async def test_client_proto_packet_received() -> None:
    """
    Ensure we properly process received packets
    """
    proto = tpt.SNMPClientProtocol(b"SNMP-packet")
    proto.datagram_received(b"fake-packet", ("192.0.2.1", 42))
    result = proto.future.result()
    assert result == b"fake-packet"


@pytest.mark.asyncio
async def test_client_proto_packet_received_log(caplog: Any) -> None:
    """
    Ensure we properly process received packets
    """
    proto = tpt.SNMPClientProtocol(b"SNMP-packet")
    with caplog.at_level(logging.DEBUG):
        proto.datagram_received(b"fake-packet", ("192.0.2.1", 42))
    assert "66 61 6b" in caplog.text, "hexdump not found in logs"
    assert "192.0.2.1:42" in caplog.text, "remote endpoint not in logs"


@pytest.mark.asyncio
async def test_client_proto_packet_received_closing() -> None:
    """
    Ensure we properly close the transport if a packet is received
    """
    mock_transport = Mock()
    proto = tpt.SNMPClientProtocol(b"SNMP-packet")
    proto.connection_made(mock_transport)
    proto.datagram_received(b"fake-packet", ("192.0.2.1", 42))
    mock_transport.close.assert_called()


@pytest.mark.asyncio
async def test_client_proto_error_propagation() -> None:
    """
    Ensure we properly propagate unexpected exceptions
    """
    proto = tpt.SNMPClientProtocol(b"SNMP-packet")
    proto.error_received(ValueError("Whoops"))
    with pytest.raises(ValueError) as exc:
        proto.future.result()
    assert exc.match("Whoops")


@pytest.mark.asyncio
async def test_client_proto_error_logging(caplog: Any) -> None:
    """
    Ensure we properly logs unexpected exceptions
    """
    proto = tpt.SNMPClientProtocol(b"SNMP-packet")
    with caplog.at_level(logging.DEBUG):
        proto.error_received(ValueError("Whoops"))
    assert "Whoops" in caplog.text
    assert "ValueError" in caplog.text


@pytest.mark.asyncio
async def test_client_proto_get_data() -> None:
    """
    Ensure we can fetch the data asynchronously
    """
    mock_transport = Mock()
    proto = tpt.SNMPClientProtocol(b"SNMP-packet")
    proto.connection_made(mock_transport)
    proto.datagram_received(b"fake-packet", ("192.0.2.1", 42))
    data = await proto.get_data(3)
    assert data == b"fake-packet"


@pytest.mark.asyncio
async def test_client_proto_get_data_timeout() -> None:
    """
    Ensure we handle timeouts properly
    """
    mock_transport = Mock()
    proto = tpt.SNMPClientProtocol(b"SNMP-packet")
    proto.connection_made(mock_transport)
    proto.error_received(socket.timeout(10))
    with pytest.raises(Timeout) as exc:
        await proto.get_data(10)
    assert exc.match("10 second")


def test_default_trap_handler(caplog: Any) -> None:
    with caplog.at_level(logging.DEBUG):
        tpt.default_trap_handler(
            SocketResponse(b"fake-payload", SocketInfo("192.0.2.1", 42))
        )
    assert "fake-payload" in caplog.text
    assert "192.0.2.1:42" in caplog.text
