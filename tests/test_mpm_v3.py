# type: ignore
import asyncio
from unittest.mock import Mock, patch

import pytest
from x690.types import Integer, ObjectIdentifier, OctetString

import puresnmp.plugins.mpm as mpm
import puresnmp_plugins.security.usm as usm
from puresnmp.adt import HeaderData, Message, ScopedPDU, V3Flags
from puresnmp.credentials import V2C, V3
from puresnmp.pdu import (
    BulkGetRequest,
    GetNextRequest,
    GetRequest,
    GetResponse,
    InformRequest,
    PDUContent,
    Report,
    SetRequest,
    Trap,
)
from puresnmp.varbind import VarBind
from puresnmp_plugins.mpm.v3 import is_confirmed
from puresnmp_plugins.security.usm import USMSecurityParameters

from unittest.mock import AsyncMock


@pytest.fixture
def mock_handler():
    data = bytes(
        Message(
            Integer(3),
            HeaderData(123, 65000, V3Flags(False, False, False), 3),
            bytes(
                USMSecurityParameters(
                    b"engine-id", 1, 2, b"username", b"auth", b"priv"
                )
            ),
            ScopedPDU(
                OctetString(b"engine-id"),
                OctetString(b"context"),
                GetResponse(
                    PDUContent(
                        123,
                        [
                            VarBind(
                                ObjectIdentifier(),
                                Integer(10),
                            )
                        ],
                    ),
                ),
            ),
        )
    )

    mock = AsyncMock(return_value=data)
    yield mock


@pytest.mark.asyncio
async def test_encode(mock_handler):
    instance = mpm.create(3, mock_handler, {})
    pdu = GetRequest(PDUContent(123, []))
    with patch(
        "puresnmp_plugins.security.usm.get_request_id", return_value=123
    ):
        result = await instance.encode(
            123, V3("username", None, None), b"engine-id", b"context", pdu
        )
    # simple sanity check on length. We could decode it and look into the
    # innards, but this is already covered by other tests
    assert len(result.data) == 91


@pytest.mark.asyncio
async def test_encode_engine_id_default(mock_handler):
    """
    If we don't get an engine-id we take the one from the remote device
    """
    instance = mpm.create(3, mock_handler, {})
    pdu = GetRequest(PDUContent(123, []))
    with patch(
        "puresnmp_plugins.security.usm.get_request_id", return_value=123
    ):
        result = await instance.encode(
            123, V3("username", None, None), b"", b"context", pdu
        )
    # simple sanity check on length. We could decode it and look into the
    # innards, but this is already covered by other tests
    assert len(result.data) == 91


@pytest.mark.parametrize(
    "pdu, expected",
    [
        (GetRequest(PDUContent(1, [])), True),
        (GetNextRequest(PDUContent(1, [])), True),
        (BulkGetRequest(1, 0, 1), True),
        (SetRequest(PDUContent(1, [])), True),
        (InformRequest(PDUContent(1, [])), True),
        (GetResponse(PDUContent(1, [])), False),
        (Trap(PDUContent(1, [])), False),
        (Report(PDUContent(1, [])), False),
    ],
    ids=[
        "GetRequest",
        "GetNextRequest",
        "BulkGetRequest",
        "SetRequest",
        "InformRequest",
        "GetResponse",
        "Trap",
        "Report",
    ],
)
def test_is_confirmed(pdu, expected):
    """
    Ensure only Confirmed Class PDUs request a reportable response (RFC 3412)
    """
    assert is_confirmed(pdu) is expected


@pytest.mark.asyncio
async def test_encode_set_request_is_reportable(mock_handler):
    """
    Ensure a SET request is sent with the reportable flag so agents answer
    failures with a Report instead of dropping the request
    """
    instance = mpm.create(3, mock_handler, {})
    pdu = SetRequest(PDUContent(123, []))
    with patch(
        "puresnmp_plugins.security.usm.get_request_id", return_value=123
    ):
        result = await instance.encode(
            123, V3("username", None, None), b"engine-id", b"context", pdu
        )
    message = Message.decode(result.data)
    assert message.header.flags.reportable is True


@pytest.mark.asyncio
async def test_encode_invalid_creds():
    """
    Encoding needs V3 credentials
    """
    instance = mpm.create(3, mock_handler, {})
    with pytest.raises(TypeError) as exc:
        await instance.encode(123, V2C("community"), b"", b"", None)
    exc.match("[vV]3")


def test_decode():
    raw_response = (
        b"0Y"
        b"\x02\x01\x03"
        b"0\x0e"
        b"\x02\x01{"
        b"\x02\x03\x00\xff\xe3"
        b"\x04\x01\x04"
        b"\x02\x01\x03"
        b"\x04!0\x1f\x04\tengine-id"
        b"\x02\x01\x01"
        b"\x02\x01\x02"
        b"\x04\x08username"
        b"\x04\x00\x04\x00"
        b"0!"
        b"\x04\tengine-id"
        b"\x04\x07context"
        b"\xa0\x0b\x02\x01{\x02\x01\x00\x02\x01\x000\x00"
    )
    lcd = {}
    instance = mpm.create(3, mock_handler, lcd)
    # Responses are only accepted from the engine the request was sent to
    instance.security_model = usm.create()
    instance.security_model.set_engine_timing(b"engine-id", 1, 2)
    result = instance.decode(raw_response, V3("username", None, None))
    assert result == GetRequest(PDUContent(123, []))
