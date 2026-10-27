"""
Responses to SNMPv3 requests must be protected with the same security level
as the request and must originate from the engine the request was sent to.

See https://tools.ietf.org/html/rfc3412#section-7.2
"""

from typing import Callable, Optional

import pytest
from x690.types import Integer, ObjectIdentifier, OctetString

from puresnmp import V3, Auth, Client, Priv
from puresnmp.adt import HeaderData, Message, PlainMessage, ScopedPDU, V3Flags
from puresnmp.exc import SnmpError
from puresnmp.pdu import PDU, GetResponse, PDUContent, Report
from puresnmp.types import Counter
from puresnmp.varbind import VarBind
from puresnmp_plugins.security.usm import (
    InsufficientSecurityLevel,
    UnknownEngineId,
    USMSecurityParameters,
    apply_authentication,
    apply_encryption,
)

ENGINE = b"\x80\x00\x1f\x88\x80agent-engine"
OTHER_ENGINE = b"\x80\x00\x1f\x88\x80other-engine"
USER = "admin"
AUTH = Auth(b"authpassword", "sha1")
PRIV = Priv(b"privpassword", "aes")
SYS_DESCR = ObjectIdentifier("1.3.6.1.2.1.1.1.0")
UNKNOWN_ENGINE_IDS = ObjectIdentifier("1.3.6.1.6.3.15.1.1.4.0")
UNKNOWN_USER_NAMES = ObjectIdentifier("1.3.6.1.6.3.15.1.1.3.0")

# Recent "cryptography" releases deprecate the CFB mode used by the AES plugin
# of "puresnmp-crypto".
pytestmark = pytest.mark.filterwarnings("ignore:CFB has been moved")

TResponder = Callable[[int], bytes]


def make_response(
    pdu: PDU,
    msg_id: int,
    auth: Optional[Auth] = None,
    priv: Optional[Priv] = None,
    engine_id: bytes = ENGINE,
) -> bytes:
    """
    Create a response as an agent would send it, protected with *auth* and
    *priv* (if given).
    """
    flags = V3Flags(auth is not None, priv is not None, False)
    plain = PlainMessage(
        Integer(3),
        HeaderData(msg_id, 65507, flags, 3),
        b"",
        ScopedPDU(OctetString(engine_id), OctetString(b""), pdu),
    )
    credentials = V3(USER, auth, priv)
    message = apply_encryption(
        plain, credentials, USER.encode("ascii"), engine_id, 5, 1000
    )
    return bytes(apply_authentication(message, credentials, engine_id))


def make_discovery_response(msg_id: int) -> bytes:
    """
    Create the unauthenticated Report an agent sends during engine discovery.
    """
    params = USMSecurityParameters(ENGINE, 5, 1000, b"", b"", b"")
    pdu = Report(PDUContent(msg_id, [VarBind(UNKNOWN_ENGINE_IDS, Counter(1))]))
    return bytes(
        PlainMessage(
            Integer(3),
            HeaderData(msg_id, 65507, V3Flags(False, False, False), 3),
            bytes(params),
            ScopedPDU(OctetString(ENGINE), OctetString(b""), pdu),
        )
    )


def make_client(credentials: V3, responder: TResponder) -> Client:
    """
    Create a client talking to a fake agent.

    Discovery requests are answered by the fake agent itself. All other
    requests are answered by *responder*, which is called with the
    message-id of the request.
    """

    async def sender(endpoint, packet, timeout=1, retries=1, **_):
        # pylint: disable=unused-argument
        request = Message.decode(packet)
        msg_id = request.header.message_id
        params = USMSecurityParameters.decode(request.security_parameters)
        if not params.user_name:
            return make_discovery_response(msg_id)
        return responder(msg_id)

    return Client("192.0.2.1", credentials, sender=sender)


def response_pdu(msg_id: int) -> PDU:
    """
    Create a GetResponse PDU carrying agent data.
    """
    return GetResponse(
        PDUContent(msg_id, [VarBind(SYS_DESCR, OctetString(b"agent-data"))])
    )


def report_pdu(msg_id: int, oid: ObjectIdentifier) -> PDU:
    """
    Create a Report PDU for the counter *oid*.
    """
    return Report(PDUContent(msg_id, [VarBind(oid, Counter(1))]))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "credentials, response_auth, response_priv",
    [
        pytest.param(V3(USER, AUTH, PRIV), None, None, id="authPriv/noAuth"),
        pytest.param(V3(USER, AUTH, PRIV), AUTH, None, id="authPriv/noPriv"),
        pytest.param(V3(USER, AUTH, None), None, None, id="authNoPriv/noAuth"),
    ],
)
async def test_reject_insufficient_level(
    credentials, response_auth, response_priv
):
    """
    A response protected less than required by the credentials must be
    rejected, even if message-id, request-id and user-name match.
    """

    def responder(msg_id: int) -> bytes:
        return make_response(
            response_pdu(msg_id), msg_id, response_auth, response_priv
        )

    client = make_client(credentials, responder)
    with pytest.raises(InsufficientSecurityLevel):
        await client.get(SYS_DESCR)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "credentials",
    [
        pytest.param(V3(USER, AUTH, PRIV), id="authPriv"),
        pytest.param(V3(USER, AUTH, None), id="authNoPriv"),
        pytest.param(V3(USER, None, None), id="noAuthNoPriv"),
    ],
)
async def test_accept_matching_level(credentials):
    """
    A response protected as required by the credentials is accepted.
    """

    def responder(msg_id: int) -> bytes:
        return make_response(
            response_pdu(msg_id), msg_id, credentials.auth, credentials.priv
        )

    client = make_client(credentials, responder)
    result = await client.get(SYS_DESCR)
    assert result == OctetString(b"agent-data")


@pytest.mark.asyncio
async def test_unauthenticated_report_is_error():
    """
    Agents send unauthenticated Reports for USM errors. Those must still be
    surfaced as the error they report.
    """

    def responder(msg_id: int) -> bytes:
        return make_response(report_pdu(msg_id, UNKNOWN_USER_NAMES), msg_id)

    client = make_client(V3(USER, AUTH, PRIV), responder)
    with pytest.raises(SnmpError, match="Unknown user-name") as exc:
        await client.get(SYS_DESCR)
    assert not isinstance(exc.value, InsufficientSecurityLevel)


@pytest.mark.asyncio
async def test_unauthenticated_report_never_returns_data():
    """
    An unauthenticated Report without a known USM error must not be returned
    as data.
    """

    def responder(msg_id: int) -> bytes:
        return make_response(report_pdu(msg_id, SYS_DESCR), msg_id)

    client = make_client(V3(USER, AUTH, PRIV), responder)
    with pytest.raises(InsufficientSecurityLevel):
        await client.get(SYS_DESCR)


@pytest.mark.asyncio
async def test_reject_other_engine():
    """
    A response must originate from the engine the request was sent to, even
    if it is correctly protected for that other engine.
    """

    def responder(msg_id: int) -> bytes:
        return make_response(
            response_pdu(msg_id), msg_id, AUTH, PRIV, engine_id=OTHER_ENGINE
        )

    client = make_client(V3(USER, AUTH, PRIV), responder)
    with pytest.raises(UnknownEngineId):
        await client.get(SYS_DESCR)
