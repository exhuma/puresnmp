import random
from binascii import unhexlify
from dataclasses import replace
from unittest.mock import Mock, patch

import pytest
from x690.types import Integer, ObjectIdentifier, OctetString, Sequence

import puresnmp.plugins.security as sec
import puresnmp_plugins.security.null as null
import puresnmp_plugins.security.usm as usm
import puresnmp_plugins.security.v1 as v1
import puresnmp_plugins.security.v2c as v2c
from puresnmp.adt import (
    EncryptedMessage,
    HeaderData,
    Message,
    PlainMessage,
    ScopedPDU,
    V3Flags,
)
from puresnmp.credentials import V2C, V3, Auth, Priv
from puresnmp.exc import InvalidResponseId, SnmpError
from puresnmp.pdu import GetRequest, GetResponse, PDUContent
from puresnmp.varbind import VarBind


def make_msg(cls=PlainMessage):
    return cls(
        3,
        HeaderData(123, 234, V3Flags(True, True, True), 3),
        bytes(
            Sequence(
                [
                    OctetString(b"engine-id"),
                    Integer(1),
                    Integer(2),
                    OctetString(b"user-name"),
                    OctetString(b"auth-params"),
                    OctetString(b"priv_params"),
                ]
            )
        ),
        GetRequest(PDUContent(123, [])),
    )


@pytest.mark.parametrize(
    "identifier, cls",
    [
        (0, null.NullSecurityModel),
        (1, v1.SNMPv1SecurityModel),
        (2, v2c.SNMPv2cSecurityModel),
        (3, usm.UserSecurityModel),
    ],
)
def test_create(identifier, cls):
    model = sec.create(identifier)
    assert isinstance(model, cls)


def test_usm_reset_digest():
    message = Message(
        3,
        HeaderData(123, 234, V3Flags(True, True, True), 3),
        bytes(
            Sequence(
                [
                    OctetString(b"engine-id"),
                    Integer(1),
                    Integer(2),
                    OctetString(b"user-name"),
                    OctetString(b"auth-params"),
                    OctetString(b"priv_params"),
                ]
            )
        ),
        GetRequest(PDUContent(123, [])),
    )
    expected = Message(
        3,
        HeaderData(123, 234, V3Flags(True, True, True), 3),
        bytes(
            Sequence(
                [
                    OctetString(b"engine-id"),
                    Integer(1),
                    Integer(2),
                    OctetString(b"user-name"),
                    OctetString(12 * b"\x00"),
                    OctetString(b"priv_params"),
                ]
            )
        ),
        GetRequest(PDUContent(123, [])),
    )
    result = usm.reset_digest(message)
    assert result == expected


def test_usm_pretty_sec():
    instance = usm.USMSecurityParameters(
        b"engine-id", 123, 234, b"username", b"auth", b"priv"
    )
    result = instance.pretty()
    assert isinstance(result, str)
    assert "engine-id" in result
    assert "123" in result
    assert "234" in result
    assert "username" in result
    assert "auth" in result
    assert "priv" in result


def test_set_timing():
    instance = usm.UserSecurityModel()
    instance.set_engine_timing(123, 234, 345)
    expected = {
        123: {
            "authoritative_engine_boots": 234,
            "authoritative_engine_time": 345,
        }
    }
    instance.local_config == expected


def test_request_message_invalid_creds():
    """
    We expect an error if we call an USM function with unsupported creds.
    """
    instance = usm.UserSecurityModel()
    with pytest.raises(TypeError):
        instance.generate_request_message(
            make_msg(),
            b"engine-id",
            V2C("community"),
        )


@pytest.mark.dependency()
def test_request_message_nanp():
    message = make_msg()
    instance = usm.UserSecurityModel()
    instance.local_config[b"engine-id"] = {
        "authoritative_engine_boots": 1,
        "authoritative_engine_time": 12,
    }
    result = instance.generate_request_message(
        message,
        b"engine-id",
        V3("username", None, None),
    )
    expected = PlainMessage(
        version=3,
        header=HeaderData(
            message_id=123,
            message_max_size=234,
            flags=V3Flags(auth=True, priv=True, reportable=True),
            security_model=3,
        ),
        security_parameters=(
            b"0\x1f\x04\tengine-id"
            b"\x02\x01\x01"
            b"\x02\x01\x0c"
            b"\x04\x08username"
            b"\x04\x00"
            b"\x04\x00"
        ),
        scoped_pdu=GetRequest(PDUContent(123, [])),
    )
    assert result == expected


@pytest.mark.dependency(depends=["test_request_message_nanp"])
def test_request_message_anp():
    message = make_msg()
    instance = usm.UserSecurityModel()
    instance.local_config[b"engine-id"] = {
        "authoritative_engine_boots": 1,
        "authoritative_engine_time": 12,
    }
    result = instance.generate_request_message(
        message,
        b"engine-id",
        V3("username", Auth(b"authkey", "md5"), None),
    )
    expected = PlainMessage(
        version=3,
        header=HeaderData(
            message_id=123,
            message_max_size=234,
            flags=V3Flags(auth=True, priv=True, reportable=True),
            security_model=3,
        ),
        security_parameters=(
            b"0+\x04\tengine-id"
            b"\x02\x01\x01"
            b"\x02\x01\x0c"
            b"\x04\x08username"
            b"\x04\x0c>\xb8\xff\x7fA<\x00\xfa\x066r\xed"
            b"\x04\x00"
        ),
        scoped_pdu=GetRequest(PDUContent(123, [])),
    )
    assert result == expected


@pytest.mark.asyncio
async def test_send_disco():
    instance = usm.UserSecurityModel()
    disco_response = Message(
        Integer(3),
        HeaderData(123, 65507, V3Flags(False, False, False), 3),
        bytes(
            Sequence(
                [
                    OctetString(b"engine-id"),
                    Integer(1),
                    Integer(75101),
                    OctetString(b""),
                    OctetString(b""),
                    OctetString(b""),
                ]
            )
        ),
        ScopedPDU(
            OctetString(b"engine-id"),
            OctetString(b"context-name"),
            GetResponse(
                PDUContent(
                    123,
                    [
                        VarBind(
                            ObjectIdentifier("1.3.6.1.6.3.15.1.1.4.0"),
                            Integer(6),
                        )
                    ],
                )
            ),
        ),
    )

    async def fake_transport(data: bytes) -> bytes:
        return bytes(disco_response)

    with patch(
        "puresnmp_plugins.security.usm.get_request_id", return_value=123
    ):
        result = await instance.send_discovery_message(fake_transport)

    expected = usm.DiscoData(b"engine-id", 1, 75101, 6)
    assert result == expected


def test_mismatching_ids():
    with pytest.raises(InvalidResponseId) as exc:
        usm.validate_response_id(1, 2)
    exc.match(r"[iI]nvalid.*id")


def test_missing_enc_method():
    with pytest.raises(usm.UnsupportedSecurityLevel):
        usm.apply_encryption(
            None, V3(b"", Auth(b"", ""), Priv(b"foo", "")), b"", b"", 0, 0
        )


def test_missing_auth_method():
    with pytest.raises(usm.UnsupportedSecurityLevel):
        usm.apply_authentication(
            None, V3(b"", Auth(b"foo", ""), Priv(b"foo", "")), b""
        )


def test_auth_error():
    with pytest.raises(usm.AuthenticationError) as exc:
        usm.apply_authentication(None, V3(b"", Auth(b"foo", "md5"), None), b"")
    exc.match(r"NoneType.*has no attribute")


def test_incoming_noauth():
    msg = replace(make_msg(), header=HeaderData(1, 1, V3Flags(), 1))
    usm.verify_authentication(
        msg,
        V3(b"", None, None),
        usm.USMSecurityParameters(b"", 1, 1, b"", b"", b""),
    )


def test_missing_auth():
    msg = replace(make_msg(), header=HeaderData(1, 1, V3Flags(True), 1))
    with pytest.raises(usm.UnsupportedSecurityLevel) as exc:
        usm.verify_authentication(
            msg,
            V3(b"", None, None),
            usm.USMSecurityParameters(b"", 1, 1, b"", b"", b""),
        )
    exc.match(r"auth.*missing")


def test_incoming_auth_error():
    msg = replace(make_msg(), header=HeaderData(1, 1, V3Flags(True), 1))
    with pytest.raises(usm.AuthenticationError) as exc:
        with patch("puresnmp_plugins.security.usm.auth") as auth:
            mck = Mock()
            mck.authenticate_incoming_message.return_value = False

            auth.create.return_value = mck
            usm.verify_authentication(
                msg,
                V3(b"", Auth(b"foo", "md5"), None),
                usm.USMSecurityParameters(b"", 1, 1, b"", b"", b""),
            )
    exc.match(r"authentic")


def test_incoming_priv_error():
    msg = replace(
        make_msg(EncryptedMessage),
        header=HeaderData(1, 1, V3Flags(True, True), 1),
    )
    with pytest.raises(usm.DecryptionError) as exc:
        with patch("puresnmp_plugins.security.usm.priv") as priv:
            mck = Mock()
            mck.decrypt_data.side_effect = Exception("yoinks")

            priv.create.return_value = mck
            usm.decrypt_message(
                replace(msg, scoped_pdu=OctetString(b"foo")),
                V3(b"", Auth(b"foo", "md5"), Priv(b"foo", "des")),
            )
    exc.match(r"decrypt.*yoinks")


def test_decrypt_noop():
    """
    An incoming message which doesn't have the "privacy" flag does not need
    to be decrypted.
    """
    msg = replace(make_msg(PlainMessage), header=HeaderData(1, 1, V3Flags(), 1))
    result = usm.decrypt_message(msg, V3(b"", None, None))
    assert result is msg


def test_incoming_cred_version():
    """
    processing incoming messages with invalid credentials should raise an error
    """
    instance = usm.UserSecurityModel()
    with pytest.raises(SnmpError) as exc:
        instance.process_incoming_message(make_msg(), V2C("community"))
    exc.match(r"credentials.*V3")


def test_incoming_user_match():
    """
    An incoming message should match with the username in the credentials
    """
    instance = usm.UserSecurityModel()
    with pytest.raises(SnmpError) as exc:
        instance.process_incoming_message(
            make_msg(), V3("the-user", None, None)
        )
    exc.match(r"user.*user-name")
