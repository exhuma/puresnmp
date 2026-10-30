"""
Tests for the wrapping of decoding errors in ``InvalidMessage``.
"""

import logging

import pytest
from x690.exc import X690Error
from x690.types import ObjectIdentifier as OID

from puresnmp.credentials import V2C
from puresnmp.exc import FaultySNMPImplementation, InvalidMessage, SnmpError
from puresnmp.plugins.mpm import decoding_boundary
from puresnmp_plugins.security.usm import AuthenticationError

GARBAGE = b"\x30\x82\x01"


@pytest.mark.asyncio
async def test_truncated_response_raises_invalid_message(mocked_raw):
    """
    Ensure a truncated response is reported as InvalidMessage.
    """
    mocked_raw.sender.set_values([GARBAGE])
    with mocked_raw.reconfigure(credentials=V2C("public")):
        with pytest.raises(InvalidMessage) as exc_info:
            await mocked_raw.get(OID("1.2.3"))
    assert exc_info.value.data == GARBAGE
    assert exc_info.value.__cause__ is not None


@pytest.mark.parametrize(
    "handled", [SnmpError, X690Error, ValueError, IndexError, LookupError]
)
@pytest.mark.parametrize("raised", [IndexError, ValueError, X690Error])
def test_invalid_message_is_catchable_by_old_handlers(raised, handled):
    """
    Ensure the new exception is caught by handlers for puresnmp errors and
    by handlers written for the errors that escaped before.
    """
    with pytest.raises(handled) as exc_info:
        with decoding_boundary(GARBAGE):
            raise raised("boom")
    assert isinstance(exc_info.value, InvalidMessage)


@pytest.mark.parametrize(
    "exc",
    [
        AuthenticationError("bad"),
        FaultySNMPImplementation("bad"),
    ],
)
def test_puresnmp_errors_pass_through(exc):
    """
    Ensure intentionally raised puresnmp errors are not re-wrapped.
    """
    with pytest.raises(type(exc)) as exc_info:
        with decoding_boundary(GARBAGE):
            raise exc
    assert exc_info.value is exc
    assert not isinstance(exc_info.value, InvalidMessage)


@pytest.mark.parametrize("exc", [KeyError("x"), TypeError("x")])
def test_other_errors_pass_through(exc):
    """
    Ensure unrelated exceptions (including programming errors like
    TypeError) are left alone.
    """
    with pytest.raises(type(exc)) as exc_info:
        with decoding_boundary(GARBAGE):
            raise exc
    assert exc_info.value is exc
    assert not isinstance(exc_info.value, InvalidMessage)


def test_hexdump_logged_at_debug(caplog):
    """
    Ensure the packet hexdump is logged at DEBUG.
    """
    with caplog.at_level(logging.DEBUG, logger="puresnmp.plugins.mpm"):
        with pytest.raises(InvalidMessage):
            with decoding_boundary(GARBAGE):
                raise IndexError("boom")
    records = [r for r in caplog.records if r.name == "puresnmp.plugins.mpm"]
    assert len(records) == 1
    assert records[0].levelno == logging.DEBUG
    assert (
        records[0]
        .getMessage()
        .startswith("Received message could not be decoded:\n")
    )
    assert "30 82 01" in records[0].getMessage()
