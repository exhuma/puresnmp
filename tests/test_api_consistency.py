"""
Consistency of the public API: ``getnext`` handling of missing objects,
``errors`` pass-through in ``PyWrapper`` and deprecation of ``loop``.
"""

import asyncio
import warnings
from unittest.mock import AsyncMock, Mock, patch

import pytest
from x690.types import Integer, ObjectIdentifier as OID

from puresnmp import PyWrapper
from puresnmp.api.raw import Client, register_trap_callback
from puresnmp.const import ERRORS_STRICT, ERRORS_WARN
from puresnmp.pdu import NoSuchInstance, NoSuchObject
from puresnmp.transport import Endpoint, listen, send_udp
from puresnmp.varbind import VarBind

from .conftest import AsyncIter


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", [NoSuchObject, NoSuchInstance])
async def test_getnext_returns_missing_value(mocked_raw, missing):
    """
    Ensure getnext keeps returning a missing value as a varbind in 2.x

    Raising NoSuchOID instead is a breaking change planned for 3.0.
    """
    varbind = VarBind(OID("1.2.3"), missing())
    mocked_raw.multigetnext = AsyncMock(return_value=[varbind])
    assert await mocked_raw.getnext(OID("1.2.3")) == varbind


@pytest.mark.asyncio
async def test_getnext_returns_regular_varbind(mocked_raw):
    """
    Ensure getnext still returns the varbind for regular values
    """
    varbind = VarBind(OID("1.2.3.4"), Integer(1))
    mocked_raw.multigetnext = AsyncMock(return_value=[varbind])
    assert await mocked_raw.getnext(OID("1.2.3")) == varbind


@pytest.mark.asyncio
@pytest.mark.parametrize("errors", [ERRORS_STRICT, ERRORS_WARN])
async def test_pythonic_multiwalk_passes_errors(errors):
    """
    Ensure PyWrapper.multiwalk hands "errors" on to the raw client
    """
    raw_client = Mock(spec=Client)
    raw_client.multiwalk.return_value = AsyncIter([])
    client = PyWrapper(client=raw_client)
    _ = [row async for row in client.multiwalk(["1.2.3"], errors=errors)]
    raw_client.multiwalk.assert_called_once_with([OID("1.2.3")], errors=errors)


@pytest.mark.asyncio
async def test_pythonic_multiwalk_errors_default():
    """
    Ensure PyWrapper.multiwalk is strict by default, like the raw client
    """
    raw_client = Mock(spec=Client)
    raw_client.multiwalk.return_value = AsyncIter([])
    client = PyWrapper(client=raw_client)
    _ = [row async for row in client.multiwalk(["1.2.3"])]
    raw_client.multiwalk.assert_called_once_with(
        [OID("1.2.3")], errors=ERRORS_STRICT
    )


@pytest.mark.asyncio
async def test_send_udp_loop_deprecated():
    """
    Ensure passing "loop" to send_udp warns, and omitting it does not
    """
    loop = asyncio.get_running_loop()
    fake = AsyncMock(side_effect=RuntimeError("stop"))
    with patch.object(loop, "create_datagram_endpoint", fake):
        with pytest.warns(DeprecationWarning, match="send_udp") as rec:
            with pytest.raises(RuntimeError):
                await send_udp(Endpoint("127.0.0.1", 9), b"x", loop=loop)
        assert rec[0].filename == __file__
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            with pytest.raises(RuntimeError):
                await send_udp(Endpoint("127.0.0.1", 9), b"x")


@pytest.mark.asyncio
async def test_listen_loop_deprecated():
    """
    Ensure passing "loop" to listen warns, and omitting it does not
    """
    loop = asyncio.get_running_loop()
    fake = AsyncMock()
    with patch.object(loop, "create_datagram_endpoint", fake):
        with pytest.warns(DeprecationWarning, match="listen"):
            await listen("127.0.0.1", 0, lambda _: None, loop)
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            await listen("127.0.0.1", 0, lambda _: None)


def test_register_trap_callback_listens_on_given_loop():
    """
    Ensure the trap listener is created on the loop passed in, even though
    the loop is no longer handed down to listen().
    """
    loop = asyncio.new_event_loop()
    try:
        fake = AsyncMock()
        with patch.object(loop, "create_datagram_endpoint", fake):
            with pytest.warns(DeprecationWarning):
                register_trap_callback(lambda _: None, loop=loop)
        fake.assert_awaited_once()
    finally:
        loop.close()


def test_register_trap_callback_loop_deprecated():
    """
    Ensure register_trap_callback warns exactly once if "loop" is passed
    """

    async def fake_listen(address, port, callback, loop=None):
        pass

    loop = asyncio.new_event_loop()
    try:
        with patch("puresnmp.api.raw.listen", fake_listen):
            with pytest.warns(DeprecationWarning, match="register_trap") as rec:
                register_trap_callback(lambda _: None, loop=loop)
            assert len(rec) == 1
            assert rec[0].filename == __file__
            with (
                warnings.catch_warnings(),
                patch("puresnmp.api.raw.get_event_loop", return_value=loop),
            ):
                warnings.simplefilter("error", DeprecationWarning)
                other = register_trap_callback(lambda _: None, loop=None)
            assert other is loop
    finally:
        loop.close()
