"""
Tests for the trap receiver in ``puresnmp.api.raw``.
"""

import asyncio
from unittest.mock import patch

from x690.types import Integer, ObjectIdentifier, OctetString, Sequence

from puresnmp.api.pythonic import TrapInfo
from puresnmp.api.raw import register_trap_callback
from puresnmp.pdu import PDUContent, Trap
from puresnmp.types import TimeTicks
from puresnmp.typevars import SocketInfo, SocketResponse
from puresnmp.varbind import VarBind

UPTIME = ObjectIdentifier("1.3.6.1.2.1.1.3.0")
TRAP_OID = ObjectIdentifier("1.3.6.1.6.3.1.1.4.1.0")
VARBINDS = [
    VarBind(UPTIME, TimeTicks(1234)),
    VarBind(TRAP_OID, ObjectIdentifier("1.3.6.1.4.1.8072.2.3.0.1")),
    VarBind(ObjectIdentifier("1.3.6.1.4.1.8072.2.3.2.1"), Integer(42)),
]


def _receive():
    """
    Feed a v2c trap through the callback and return what the user got.
    """
    captured = {}
    received = []

    async def fake_listen(address, port, callback, loop):
        captured["decode"] = callback

    async def user_callback(trap):
        received.append(trap)

    message = Sequence(
        [
            Integer(1),
            OctetString(b"public"),
            Trap(PDUContent(1234, VARBINDS)),
        ]
    )
    loop = asyncio.new_event_loop()
    try:
        with patch("puresnmp.api.raw.listen", fake_listen):
            register_trap_callback(user_callback, loop=loop)

        async def deliver():
            captured["decode"](
                SocketResponse(bytes(message), SocketInfo("192.0.2.1", 162))
            )
            await asyncio.sleep(0)

        loop.run_until_complete(deliver())
    finally:
        loop.close()
    return received


def test_trap_callback_receives_trap():
    """
    Ensure the callback receives the decoded trap with its varbinds.
    """
    received = _receive()
    assert len(received) == 1
    assert isinstance(received[0], Trap)
    assert received[0].value.varbinds == VARBINDS


def test_trap_origin_is_set():
    """
    Ensure the trap knows its sender, so ``TrapInfo.origin`` works.
    """
    trap = _receive()[0]
    assert trap.source == SocketInfo("192.0.2.1", 162)
    assert TrapInfo(trap).origin == "192.0.2.1"


def test_undecodable_trap_raises_invalid_message():
    """
    Ensure a garbage trap packet raises InvalidMessage in the receiver.
    """
    import pytest

    from puresnmp.exc import InvalidMessage

    captured = {}

    async def fake_listen(address, port, callback, loop):
        captured["decode"] = callback

    async def user_callback(trap):  # pragma: no cover
        pass

    loop = asyncio.new_event_loop()
    try:
        with patch("puresnmp.api.raw.listen", fake_listen):
            register_trap_callback(user_callback, loop=loop)
        with pytest.raises(InvalidMessage):
            captured["decode"](
                SocketResponse(b"\x30\x82\x01", SocketInfo("192.0.2.1", 162))
            )
    finally:
        loop.close()
