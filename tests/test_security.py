import random
from binascii import unhexlify
from dataclasses import replace
from unittest.mock import Mock, patch

import pytest
from x690.types import Integer, ObjectIdentifier, OctetString, Sequence

import puresnmp.security as sec
import puresnmp.security.null as null
import puresnmp.security.usm as usm
import puresnmp.security.v1 as v1
import puresnmp.security.v2c as v2c
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


@pytest.mark.dependency(depends=["test_request_message_anp"])
def test_request_message_ap_des():
    # Apply static random seed for testing
    random.seed(123)
    message = make_msg()
    instance = usm.UserSecurityModel()
    instance.local_config[b"engine-id"] = {
        "authoritative_engine_boots": 1,
        "authoritative_engine_time": 12,
    }
    result = instance.generate_request_message(
        message,
        b"engine-id",
        V3("username", Auth(b"authkey", "md5"), Priv(b"pkey", "des")),
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
            b"03\x04\tengine-id"
            b"\x02\x01\x01"
            b"\x02\x01\x0c"
            b"\x04\x08username"
            b"\x04\x0c/\xa6\xe1 \x93\xca}\xe5e<U/"
            b"\x04\x08\x00\x00\x00\x01\x00\x00\x00g"
        ),
        scoped_pdu=OctetString(b"\xde\xe24\x01b\xbdk\x9b#\x01\xe4|\x8a\xe6\r7"),
    )
    assert result == expected


@pytest.mark.dependency(depends=["test_request_message_anp"])
def test_request_message_ap_aes():
    # Apply static random seed for testing
    random.seed(123)
    message = make_msg()
    instance = usm.UserSecurityModel()
    instance.local_config[b"engine-id"] = {
        "authoritative_engine_boots": 1,
        "authoritative_engine_time": 12,
    }
    result = instance.generate_request_message(
        message,
        b"engine-id",
        V3("username", Auth(b"authkey", "md5"), Priv(b"pkey", "aes")),
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
            b"03\x04\tengine-id"
            b"\x02\x01\x01"
            b"\x02\x01\x0c"
            b"\x04\x08username"
            b"\x04\x0co\xc3\x03\xde\xbe\x1c\xed\xb3\x18\xe8\x1b\x8a"
            b"\x04\x08D\x86}\xb3\rg\xb3g"
        ),
        scoped_pdu=OctetString(unhexlify("437eec8e6e128dfd4b9923b679d6a24c")),
    )
    assert result.security_parameters == expected.security_parameters
    assert (
        result.scoped_pdu.value == expected.scoped_pdu.value
    ), "Invalid cipher text"


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

    with patch("puresnmp.security.usm.get_request_id", return_value=123):
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


def test_encrypt_error():
    with pytest.raises(usm.EncryptionError) as exc:
        usm.apply_encryption(
            None,
            V3(b"", Auth(b"a", "md5"), Priv(b"foo", "des")),
            b"",
            b"",
            0,
            0,
        )
    exc.match(r"NoneType.*has no attribute")


def test_missing_auth_method():
    with pytest.raises(usm.UnsupportedSecurityLevel):
        usm.apply_authentication(
            None, V3(b"", Auth(b"foo", ""), Priv(b"foo", "")), b""
        )


def test_auth_error():
    with pytest.raises(usm.AuthenticationError) as exc:
        usm.apply_authentication(None, V3(b"", Auth(b"foo", "md5"), None), b"")
    exc.match(r"NoneType.*has no attribute")


def test_incoming_message():
    message = Message(
        version=Integer(3),
        header=HeaderData(
            message_id=1610635889,
            message_max_size=65507,
            flags=V3Flags(auth=True, priv=True, reportable=False),
            security_model=3,
        ),
        security_parameters=(
            b"0:"
            b"\x04\x11\x80\x00\x1f\x88\x80\xf5\xb92\x087\x13\xff_\x00\x00\x00\x00"
            b"\x02\x01\x01"
            b"\x02\x03\x01G:"
            b"\x04\x05ninja"
            b"\x04\x0c(\x85t\xdbN\xad\xc7\x9c\xa6\xf5\x92\xdc"
            b"\x04\x08\x00\x00\x00\x01m\xfc\x986"
        ),
        scoped_pdu=OctetString(
            (
                b"\xe0\xc5\xfc\xa6m@\xaf\xc3\xd5<\t\xa9\x9e\x81\xa0\xa2\xb9"
                b"\x13\xd7\x14\xe8J\xa84C,\xbb \xd9\xbc\x06]\x08he\xe6/\x06"
                b"y'\xf4x\xc7#=\x07^n\x8d\xbf\xcem\x82\xfa\xc67w/?\xcd\xec"
                b"\x89\xe9{"
            )
        ),
    )
    instance = usm.UserSecurityModel()
    result = instance.process_incoming_message(
        message,
        V3(
            "ninja",
            Auth(b"theauthpass", "md5"),
            Priv(b"privpass", "des"),
        ),
    )
    expected = Message(
        version=Integer(3),
        header=HeaderData(
            message_id=1610635889,
            message_max_size=65507,
            flags=V3Flags(auth=True, priv=True, reportable=False),
            security_model=3,
        ),
        security_parameters=(
            b"0:"
            b"\x04\x11\x80\x00\x1f\x88\x80\xf5\xb92\x087\x13\xff_\x00\x00\x00\x00"
            b"\x02\x01\x01"
            b"\x02\x03\x01G:"
            b"\x04\x05ninja"
            b"\x04\x0c(\x85t\xdbN\xad\xc7\x9c\xa6\xf5\x92\xdc"
            b"\x04\x08\x00\x00\x00\x01m\xfc\x986"
        ),
        scoped_pdu=ScopedPDU(
            context_engine_id=OctetString(b"\x01\x00&4\x04puresnmp-26938"),
            context_name=OctetString(b""),
            data=GetResponse(
                PDUContent(
                    1610635889,
                    [
                        VarBind(
                            ObjectIdentifier("1.3.6.1.6.3.16.1.1.1.1.0"),
                            OctetString(b""),
                        )
                    ],
                )
            ),
        ),
    )
    assert result == expected


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
        with patch("puresnmp.security.usm.auth") as auth:
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
        with patch("puresnmp.security.usm.priv") as priv:
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
