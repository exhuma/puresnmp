from puresnmp.credentials import Auth, Priv, V2C, V3
from x690.types import Integer, OctetString, Sequence
from puresnmp.pdu import GetRequest
from puresnmp.adt import HeaderData, Message, V3Flags
import pytest
import random

import puresnmp.security as sec
import puresnmp.security.null as null
import puresnmp.security.usm as usm
import puresnmp.security.v1 as v1
import puresnmp.security.v2c as v2c


def make_msg():
    return Message(
        3,
        HeaderData(123, 234, V3Flags(True, True, True), 3),
        bytes(
            Sequence(
                OctetString(b"engine-id"),
                Integer(1),
                Integer(2),
                OctetString(b"user-name"),
                OctetString(b"auth-params"),
                OctetString(b"priv_params"),
            )
        ),
        GetRequest(123, []),
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
def test_null(identifier, cls):
    model = sec.create(identifier)
    assert isinstance(model, cls)


def test_usm_reset_digest():
    message = Message(
        3,
        HeaderData(123, 234, V3Flags(True, True, True), 3),
        bytes(
            Sequence(
                OctetString(b"engine-id"),
                Integer(1),
                Integer(2),
                OctetString(b"user-name"),
                OctetString(b"auth-params"),
                OctetString(b"priv_params"),
            )
        ),
        GetRequest(123, []),
    )
    expected = Message(
        3,
        HeaderData(123, 234, V3Flags(True, True, True), 3),
        bytes(
            Sequence(
                OctetString(b"engine-id"),
                Integer(1),
                Integer(2),
                OctetString(b"user-name"),
                OctetString(12 * b"\x00"),
                OctetString(b"priv_params"),
            )
        ),
        GetRequest(123, []),
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
    expected = Message(
        version=3,
        global_data=HeaderData(
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
        scoped_pdu=GetRequest(123, []),
    )
    assert result == expected


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
    expected = Message(
        version=3,
        global_data=HeaderData(
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
        scoped_pdu=GetRequest(123, []),
    )
    assert result == expected


def test_request_message_ap():
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
    expected = Message(
        version=3,
        global_data=HeaderData(
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
