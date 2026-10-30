"""
Shared helpers for the SNMPv3 tests
"""

from x690.types import Integer, ObjectIdentifier, OctetString

from puresnmp import V3, Auth
from puresnmp.adt import HeaderData, PlainMessage, ScopedPDU, V3Flags
from puresnmp.pdu import GetResponse, PDUContent
from puresnmp.varbind import VarBind
from puresnmp_plugins.mpm.v3 import V3MPM
from puresnmp_plugins.security import usm

#: The engine ID of the (simulated) agent
ENGINE = b"\x80\x00\x1f\x88\x80agent-engine"
#: The SNMPv3 user name used in the tests
USER = "admin"
#: The OID used in the varbind of test responses
SYS_DESCR = ObjectIdentifier("1.3.6.1.2.1.1.1.0")


def make_mpm() -> V3MPM:
    """
    Create a message-processing model that already knows the agent's engine.
    """

    async def handler(_: bytes) -> bytes:  # pragma: no cover
        raise AssertionError("No network traffic expected")

    mpm = V3MPM(handler, {})
    mpm.security_model = usm.UserSecurityModel()
    mpm.security_model.set_engine_timing(ENGINE, 5, 4096)
    return mpm


def make_response(method: str, key: bytes = b"authpassword") -> bytes:
    """
    Create an authNoPriv GetResponse as an agent would send it, authenticated
    through the regular USM code path with *method* and *key*.

    The response carries one varbind with the value ``b"the-description"``.
    """
    message = PlainMessage(
        version=Integer(3),
        header=HeaderData(
            message_id=123,
            message_max_size=65507,
            flags=V3Flags(auth=True, priv=False, reportable=False),
            security_model=3,
        ),
        security_parameters=b"",
        scoped_pdu=ScopedPDU(
            OctetString(ENGINE),
            OctetString(),
            GetResponse(
                PDUContent(
                    123, [VarBind(SYS_DESCR, OctetString(b"the-description"))]
                )
            ),
        ),
    )
    agent = usm.UserSecurityModel()
    agent.set_engine_timing(ENGINE, 5, 4096)
    authed = agent.generate_request_message(
        message, ENGINE, V3(USER, Auth(key, method), None)
    )
    return bytes(authed)
