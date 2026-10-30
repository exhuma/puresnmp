"""
The digest of an incoming SNMPv3 message must be computed over the message
as received, not over a re-encoded copy of it.

Agents may use any valid BER encoding (long-form lengths, non-minimal
integers, ...). Re-encoding such a message yields different bytes and thus a
different digest.

See https://tools.ietf.org/html/rfc3414#section-6.3.2 and
https://github.com/exhuma/puresnmp/issues/122
"""

from typing import Tuple

import pytest

import puresnmp.plugins.auth as auth
from puresnmp import V3, Auth
from puresnmp.adt import Message, PlainMessage
from puresnmp.credentials import Credentials
from puresnmp.pdu import GetResponse
from puresnmp.plugins.security import SecurityModel
from puresnmp_plugins.mpm.v3 import accepts_whole_msg
from puresnmp_plugins.security import usm

from .conftest import ENGINE, USER, make_mpm, make_response

ALL_METHODS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
SYS_DESCR = bytes.fromhex("06082b06010201010100")  # 1.3.6.1.2.1.1.1.0


def tlv(tag: int, value: bytes, long_form: bool = False) -> bytes:
    """
    Encode a BER TLV. With *long_form*, the length uses the (valid but
    non-minimal) long form even when the short form would do.
    """
    if long_form or len(value) > 127:
        length = bytes([0x82]) + len(value).to_bytes(2, "big")
    else:
        length = bytes([len(value)])
    return bytes([tag]) + length + value


def make_nonminimal_response(auth_method: str, key: bytes) -> Tuple[bytes, int]:
    """
    Create an authNoPriv GetResponse with a valid digest over a non-minimal
    BER encoding, as an embedded agent might send it.

    :returns: The message and the offset of a byte inside the varbind value
    """
    plugin = auth.create(auth_method)
    length = auth.digest_length(plugin)
    header = tlv(
        0x30,
        tlv(0x02, b"\x00\x00\x00\x7b")  # msgID 123, non-minimal
        + tlv(0x02, b"\x00\x00\xff\xe3")  # msgMaxSize, non-minimal
        + tlv(0x04, b"\x01")  # auth, no priv, not reportable
        + tlv(0x02, b"\x03"),
        long_form=True,
    )
    usm_params = tlv(
        0x30,
        tlv(0x04, ENGINE)
        + tlv(0x02, b"\x00\x05")  # boots, non-minimal
        + tlv(0x02, b"\x00\x00\x10\x00")  # time, non-minimal
        + tlv(0x04, USER.encode("ascii"))
        + tlv(0x04, b"\x00" * length, long_form=True)
        + tlv(0x04, b""),
        long_form=True,
    )
    varbind = tlv(0x30, SYS_DESCR + tlv(0x04, b"the-description"))
    pdu = tlv(
        0xA2,
        tlv(0x02, b"\x00\x7b")  # request-id 123, non-minimal
        + tlv(0x02, b"\x00")
        + tlv(0x02, b"\x00")
        + tlv(0x30, varbind, long_form=True),
        long_form=True,
    )
    scoped_pdu = tlv(0x30, tlv(0x04, ENGINE) + tlv(0x04, b"") + pdu)
    unauthed = tlv(
        0x30,
        tlv(0x02, b"\x03")
        + header
        + tlv(0x04, usm_params, long_form=True)
        + scoped_pdu,
        long_form=True,
    )
    digest = plugin.authenticate_outgoing_message(key, unauthed, ENGINE)
    position = unauthed.index(b"\x00" * length)
    message = unauthed[:position] + digest + unauthed[position + len(digest) :]
    return message, message.index(b"the-description")


@pytest.mark.parametrize("auth_method", ALL_METHODS)
def test_non_minimal_encoding_authenticates(auth_method: str) -> None:
    """
    Ensure a correctly signed response using non-minimal BER encoding is
    accepted.
    """
    key = b"authpassword"
    message, _ = make_nonminimal_response(auth_method, key)
    assert bytes(Message.decode(message)) != message  # sanity check

    pdu = make_mpm().decode(message, V3(USER, Auth(key, auth_method), None))

    assert isinstance(pdu, GetResponse)
    assert pdu.value.varbinds[0].value.pythonize() == b"the-description"


@pytest.mark.parametrize("auth_method", ALL_METHODS)
def test_tampered_message_is_rejected(auth_method: str) -> None:
    """
    Ensure a response modified after signing is rejected.
    """
    key = b"authpassword"
    message, offset = make_nonminimal_response(auth_method, key)
    tampered = message[:offset] + b"T" + message[offset + 1 :]

    with pytest.raises(usm.AuthenticationError):
        make_mpm().decode(tampered, V3(USER, Auth(key, auth_method), None))


def test_tampered_digest_is_rejected() -> None:
    """
    Ensure a response with a modified digest is rejected.
    """
    key = b"authpassword"
    message, _ = make_nonminimal_response("md5", key)
    secparams = usm.USMSecurityParameters.decode(
        Message.decode(message).security_parameters
    )
    position = message.index(secparams.auth_params)
    tampered = (
        message[:position]
        + bytes([message[position] ^ 0x01])
        + message[position + 1 :]
    )

    with pytest.raises(usm.AuthenticationError):
        make_mpm().decode(tampered, V3(USER, Auth(key, "md5"), None))


def test_wrong_key_is_rejected() -> None:
    """
    Ensure a response signed with a different key is rejected.
    """
    message, _ = make_nonminimal_response("md5", b"authpassword")

    with pytest.raises(usm.AuthenticationError):
        make_mpm().decode(
            message, V3(USER, Auth(b"otherpassword", "md5"), None)
        )


def test_locate_auth_params() -> None:
    """
    Ensure the authentication parameters are found at their received
    position despite long-form lengths before them.
    """
    message, _ = make_nonminimal_response("md5", b"authpassword")
    secparams = usm.USMSecurityParameters.decode(
        Message.decode(message).security_parameters
    )

    position = usm.locate_auth_params(message)

    assert message[position] == secparams.auth_params
    assert position.start == message.index(secparams.auth_params)


def test_reset_received_digest_checks_content() -> None:
    """
    Ensure the digest is not zeroed if the located octets do not hold the
    decoded authentication parameters.
    """
    message, _ = make_nonminimal_response("md5", b"authpassword")

    with pytest.raises(usm.AuthenticationError):
        usm.reset_received_digest(message, b"\xff" * 12)


class LegacySecurityModel(SecurityModel[PlainMessage, PlainMessage]):
    """
    A third-party security model written against the puresnmp 2.0 API,
    without the *whole_msg* argument.
    """

    def process_incoming_message(  # pylint: disable=arguments-differ
        self, message: PlainMessage, credentials: Credentials
    ) -> PlainMessage:
        return message


def test_legacy_security_model_signature() -> None:
    """
    Ensure security models without the *whole_msg* argument are still called
    by the message-processing model.
    """
    mpm = make_mpm()
    mpm.security_model = LegacySecurityModel()

    pdu = mpm.decode(make_response("md5"), V3(USER, None, None))

    assert isinstance(pdu, GetResponse)
    assert pdu.value.varbinds[0].value.pythonize() == b"the-description"


class KwargsSecurityModel(SecurityModel[PlainMessage, PlainMessage]):
    """
    A security model accepting any keyword arguments.
    """

    def process_incoming_message(  # pylint: disable=arguments-differ
        self, message: PlainMessage, credentials: Credentials, **kwargs: object
    ) -> PlainMessage:
        raise AssertionError("Not called")  # pragma: no cover


@pytest.mark.parametrize(
    "model_class, expected",
    [
        (usm.UserSecurityModel, True),
        (KwargsSecurityModel, True),
        (LegacySecurityModel, False),
    ],
)
def test_accepts_whole_msg(model_class: type, expected: bool) -> None:
    """
    Ensure *whole_msg* is only passed to models declaring it (or **kwargs).
    """
    assert accepts_whole_msg(model_class) is expected
