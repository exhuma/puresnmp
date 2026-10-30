"""
The non-authoritative side must keep its own notion of the remote engine's
time and resynchronise it when the agent reports usmStatsNotInTimeWindows.

See https://tools.ietf.org/html/rfc3414#section-2.3 and
https://github.com/exhuma/puresnmp/issues/104
"""

from typing import Callable, List, Optional

import pytest
from x690.types import Integer, ObjectIdentifier, OctetString

from puresnmp import V3, Auth, Client, Priv
from puresnmp.adt import HeaderData, Message, PlainMessage, ScopedPDU, V3Flags
from puresnmp.credentials import Credentials
from puresnmp.exc import NotInTimeWindow, SnmpError
from puresnmp.pdu import PDU, GetResponse, PDUContent, Report
from puresnmp.types import Counter
from puresnmp.varbind import VarBind
from puresnmp_plugins.security import usm
from puresnmp_plugins.security.usm import (
    USMSecurityParameters,
    apply_authentication,
    apply_encryption,
)

ENGINE = b"\x80\x00\x1f\x88\x80agent-engine"
USER = "admin"
AUTH = Auth(b"authpassword", "sha1")
PRIV = Priv(b"privpassword", "aes")
SYS_DESCR = ObjectIdentifier("1.3.6.1.2.1.1.1.0")
UNKNOWN_ENGINE_IDS = ObjectIdentifier("1.3.6.1.6.3.15.1.1.4.0")
NOT_IN_TIME_WINDOWS = ObjectIdentifier("1.3.6.1.6.3.15.1.1.2.0")

# Recent "cryptography" releases deprecate the CFB mode used by the AES plugin
# of "puresnmp-crypto".
pytestmark = pytest.mark.filterwarnings("ignore:CFB has been moved")

TResponder = Callable[[int, USMSecurityParameters], bytes]


class FakeClock:
    """
    A replacement for the monotonic clock used by the USM.
    """

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    """
    Replace the clock of the USM with a controllable one.
    """
    fake = FakeClock()
    monkeypatch.setattr(usm, "clock", fake)
    return fake


def make_response(
    pdu: PDU,
    msg_id: int,
    boots: int,
    time: int,
    auth: Optional[Auth] = None,
    priv: Optional[Priv] = None,
) -> bytes:
    """
    Create a response as an agent with the given engine timing would send
    it, protected with *auth* and *priv* (if given).
    """
    flags = V3Flags(auth is not None, priv is not None, False)
    plain = PlainMessage(
        Integer(3),
        HeaderData(msg_id, 65507, flags, 3),
        b"",
        ScopedPDU(OctetString(ENGINE), OctetString(b""), pdu),
    )
    credentials = V3(USER, auth, priv)
    message = apply_encryption(
        plain, credentials, USER.encode("ascii"), ENGINE, boots, time
    )
    return bytes(apply_authentication(message, credentials, ENGINE))


def make_discovery_response(msg_id: int, boots: int, time: int) -> bytes:
    """
    Create the unauthenticated Report an agent sends during engine discovery.
    """
    params = USMSecurityParameters(ENGINE, boots, time, b"", b"", b"")
    pdu = Report(PDUContent(msg_id, [VarBind(UNKNOWN_ENGINE_IDS, Counter(1))]))
    return bytes(
        PlainMessage(
            Integer(3),
            HeaderData(msg_id, 65507, V3Flags(False, False, False), 3),
            bytes(params),
            ScopedPDU(OctetString(ENGINE), OctetString(b""), pdu),
        )
    )


def make_client(
    credentials: Credentials,
    responder: TResponder,
    sent: List[USMSecurityParameters],
    disco_boots: int = 5,
    disco_time: int = 1000,
) -> Client:
    """
    Create a client talking to a fake agent.

    Discovery requests are answered by the fake agent itself with the given
    engine timing. All other requests are recorded in *sent* and answered by
    *responder*, which is called with the message-id and the security
    parameters of the request.
    """

    async def sender(endpoint, packet, timeout=1, retries=1, **_):
        # pylint: disable=unused-argument
        request = Message.decode(packet)
        msg_id = request.header.message_id
        params = USMSecurityParameters.decode(request.security_parameters)
        if not params.user_name:
            return make_discovery_response(msg_id, disco_boots, disco_time)
        sent.append(params)
        return responder(msg_id, params)

    return Client("192.0.2.1", credentials, sender=sender)


def response_pdu(msg_id: int) -> PDU:
    """
    Create a GetResponse PDU carrying agent data.
    """
    return GetResponse(
        PDUContent(msg_id, [VarBind(SYS_DESCR, OctetString(b"agent-data"))])
    )


def time_window_report() -> PDU:
    """
    Create a usmStatsNotInTimeWindows Report PDU.
    """
    return Report(PDUContent(0, [VarBind(NOT_IN_TIME_WINDOWS, Counter(7))]))


def sent_timing(sent: List[USMSecurityParameters]) -> List[tuple]:
    """
    Extract the engine timing from recorded request security parameters.
    """
    return [
        (item.authoritative_engine_boots, item.authoritative_engine_time)
        for item in sent
    ]


@pytest.mark.asyncio
async def test_engine_time_advances(clock: FakeClock) -> None:
    """
    Ensure requests sent later carry an engine time advanced by the local
    time elapsed since the timing was learned.
    """
    credentials = V3(USER, AUTH, PRIV)
    sent: List[USMSecurityParameters] = []

    def responder(msg_id: int, _: USMSecurityParameters) -> bytes:
        return make_response(response_pdu(msg_id), msg_id, 5, 1000, AUTH, PRIV)

    client = make_client(credentials, responder, sent)
    await client.get(SYS_DESCR)
    clock.now += 200
    await client.get(SYS_DESCR)

    assert sent_timing(sent) == [(5, 1000), (5, 1200)]


@pytest.mark.asyncio
async def test_timing_updated_from_authenticated_response(
    clock: FakeClock,
) -> None:
    """
    Ensure an authenticated response with a later engine time updates the
    timing used for later requests.
    """
    credentials = V3(USER, AUTH, PRIV)
    sent: List[USMSecurityParameters] = []

    def responder(msg_id: int, _: USMSecurityParameters) -> bytes:
        return make_response(response_pdu(msg_id), msg_id, 5, 5000, AUTH, PRIV)

    client = make_client(credentials, responder, sent)
    await client.get(SYS_DESCR)
    clock.now += 10
    await client.get(SYS_DESCR)

    assert sent_timing(sent) == [(5, 1000), (5, 5010)]


@pytest.mark.asyncio
async def test_timing_not_updated_from_unauthenticated_response(
    clock: FakeClock,
) -> None:
    """
    Ensure an unauthenticated response does not change the engine timing.
    """
    credentials = V3(USER, None, None)
    sent: List[USMSecurityParameters] = []

    def responder(msg_id: int, _: USMSecurityParameters) -> bytes:
        return make_response(response_pdu(msg_id), msg_id, 9, 5000)

    client = make_client(credentials, responder, sent)
    await client.get(SYS_DESCR)
    await client.get(SYS_DESCR)

    assert sent_timing(sent) == [(5, 1000), (5, 1000)]


@pytest.mark.asyncio
async def test_resync_on_authenticated_time_window_report(
    clock: FakeClock,
) -> None:
    """
    Ensure an authenticated notInTimeWindow Report resynchronises the engine
    timing and the request is resent once with the reported values.

    This models an agent reporting boots=0/time=0 during discovery.
    """
    credentials = V3(USER, AUTH, PRIV)
    sent: List[USMSecurityParameters] = []

    def responder(msg_id: int, params: USMSecurityParameters) -> bytes:
        timing = (
            params.authoritative_engine_boots,
            params.authoritative_engine_time,
        )
        if timing == (12, 9230468):
            return make_response(
                response_pdu(msg_id), msg_id, 12, 9230468, AUTH, PRIV
            )
        return make_response(time_window_report(), msg_id, 12, 9230468, AUTH)

    client = make_client(credentials, responder, sent, 0, 0)
    result = await client.get(SYS_DESCR)

    assert (result, sent_timing(sent)) == (
        OctetString(b"agent-data"),
        [(0, 0), (12, 9230468)],
    )


@pytest.mark.asyncio
async def test_unauthenticated_time_window_report(clock: FakeClock) -> None:
    """
    Ensure an unauthenticated notInTimeWindow Report raises an error without
    a retry and without changing the engine timing.
    """
    credentials = V3(USER, AUTH, PRIV)
    sent: List[USMSecurityParameters] = []

    def responder(msg_id: int, _: USMSecurityParameters) -> bytes:
        return make_response(time_window_report(), msg_id, 12, 9230468)

    client = make_client(credentials, responder, sent)
    for _ in range(2):
        with pytest.raises(SnmpError, match="Not in time window") as exc:
            await client.get(SYS_DESCR)
        assert not isinstance(exc.value, NotInTimeWindow)

    assert sent_timing(sent) == [(5, 1000), (5, 1000)]


@pytest.mark.asyncio
async def test_second_time_window_report_propagates(clock: FakeClock) -> None:
    """
    Ensure a second consecutive notInTimeWindow Report is raised after
    exactly one retry.
    """
    credentials = V3(USER, AUTH, PRIV)
    sent: List[USMSecurityParameters] = []

    def responder(msg_id: int, _: USMSecurityParameters) -> bytes:
        return make_response(time_window_report(), msg_id, 12, 9230468, AUTH)

    client = make_client(credentials, responder, sent)
    with pytest.raises(NotInTimeWindow):
        await client.get(SYS_DESCR)

    assert len(sent) == 2


# Report received from an Alcatel device in response to the first authPriv
# request after a discovery reporting boots=0 and time=0 (GitHub issue #104).
# User "snmpv3user", auth sha1 and priv aes with "snmpv3password".
ALCATEL_ENGINE = bytes.fromhex("80001956039424e149451d")
ALCATEL_REPORT = bytes.fromhex(
    "307c02010330100204297be75e020207d004010102010304343032040b800019560394"
    "24e149451d02010c0204008cd884040a736e6d70763375736572040c13d29cdbfb7ca3"
    "57770dce6c0400302f040b80001956039424e149451d0400a81e020100020100020100"
    "30133011060a2b060106030f01010200410306266f"
)


def test_alcatel_time_window_report(clock: FakeClock) -> None:
    """
    Ensure the Report captured from an Alcatel device authenticates, raises
    NotInTimeWindow and yields the engine timing boots=12/time=9230468.
    """
    credentials = V3(
        "snmpv3user",
        Auth(b"snmpv3password", "sha1"),
        Priv(b"snmpv3password", "aes"),
    )
    model = usm.UserSecurityModel()
    model.set_engine_timing(ALCATEL_ENGINE, 0, 0)

    with pytest.raises(NotInTimeWindow):
        model.process_incoming_message(
            Message.decode(ALCATEL_REPORT), credentials
        )
    config = model.local_config[ALCATEL_ENGINE]

    assert (
        config["authoritative_engine_boots"],
        config["authoritative_engine_time"],
    ) == (12, 9230468)
