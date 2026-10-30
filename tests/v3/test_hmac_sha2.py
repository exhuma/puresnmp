"""
The HMAC-SHA-2 authentication protocols of :rfc:`7860`.

The expected keys and digests below were computed with pysnmp 7.1.30
(``pysnmp.proto.secmod.rfc7860.auth.hmacsha2.HmacSha2``), an implementation
independent of puresnmp, for the password "maplesyrup" and the engine ID
000000000000000000000002 of :rfc:`3414#appendix-A.3`. The same pysnmp code
reproduces the MD5 and SHA-1 values published in :rfc:`3414#appendix-A.3`.

See https://github.com/exhuma/puresnmp/issues/138
"""

import hashlib
import hmac
from dataclasses import replace
from types import SimpleNamespace

import pytest

import puresnmp.plugins.auth as auth
from puresnmp import V3, Auth, Priv
from puresnmp.adt import Message
from puresnmp.pdu import GetResponse
from puresnmp.util import localise_key
from puresnmp_plugins.security import usm

from .conftest import ENGINE, USER, make_mpm, make_response

PASSWORD = b"maplesyrup"
RFC_ENGINE = bytes.fromhex("000000000000000000000002")

# The message "head" + <digest-length zeroes> + "tail", authenticated by
# pysnmp with the localised key below, yields the "mac" value.
PYSNMP_VECTORS = {
    "sha224": {
        "length": 16,
        "localised": "0bd8827c6e29f8065e08e09237f177e410f69b90e1782be682075674",
        "mac": "08509e492672adac69096c362e41e9e1",
    },
    "sha256": {
        "length": 24,
        "localised": (
            "8982e0e549e866db361a6b625d84cccc"
            "11162d453ee8ce3a6445c2d6776f0f8b"
        ),
        "mac": "0b43518c6df9a46f61b4f35066b94750a79065fa64e7d77a",
    },
    "sha384": {
        "length": 32,
        "localised": (
            "3b298f16164a11184279d5432bf169e2d2a48307de02b3d3"
            "f7e2b4f36eb6f0455a53689a3937eea07319a633d2ccba78"
        ),
        "mac": (
            "1a05f5fb7366b1343e4846c0e6449d53"
            "1f44450b650606779ce9efb2d9d73d55"
        ),
    },
    "sha512": {
        "length": 48,
        "localised": (
            "22a5a36cedfcc085807a128d7bc6c2382167ad6c0dbc5fdff856740f3d84c099"
            "ad1ea87a8db096714d9788bd544047c9021e4229ce27e4c0a69250adfcffbb0b"
        ),
        "mac": (
            "c135883418801f9289cb0303e880c1b552efcd80d4272334"
            "d5e0921f2cdab426c54d3f3e9bd70fcf650edfbbd7d801f7"
        ),
    },
}

METHODS = sorted(PYSNMP_VECTORS)


def rfc_localised_key(method: str, password: bytes, engine_id: bytes) -> bytes:
    """
    Derive a localised key following the text of :rfc:`3414#section-2.6`
    and :rfc:`7860#section-4.1`, using nothing but :py:mod:`hashlib`.
    """
    expanded = (password * (1048576 // len(password) + 1))[:1048576]
    master_key = hashlib.new(method, expanded).digest()
    return hashlib.new(method, master_key + engine_id + master_key).digest()


@pytest.mark.parametrize("method", METHODS)
def test_localised_key_matches_independent_implementation(method):
    """
    Ensure the auth plugin derives the key computed by pysnmp and by a plain
    reading of the RFC.
    """
    plugin = auth.create(method)
    expected = bytes.fromhex(PYSNMP_VECTORS[method]["localised"])

    result = plugin.hasher(PASSWORD, RFC_ENGINE)

    assert result == expected
    assert result == rfc_localised_key(method, PASSWORD, RFC_ENGINE)


@pytest.mark.parametrize("method", METHODS)
def test_localise_key_accepts_method(method):
    """
    Ensure the privacy key can be localised with an SHA-2 auth method.
    """
    creds = V3(USER, Auth(b"authpassword", method), Priv(PASSWORD, "aes"))

    result = localise_key(creds, RFC_ENGINE)

    assert result == bytes.fromhex(PYSNMP_VECTORS[method]["localised"])


@pytest.mark.parametrize("method", METHODS)
def test_outgoing_digest_matches_independent_implementation(method):
    """
    Ensure the digest has the RFC 7860 length and matches the value computed
    by pysnmp and by plain :py:mod:`hmac`.
    """
    vector = PYSNMP_VECTORS[method]
    data = b"head" + b"\x00" * vector["length"] + b"tail"
    localised = rfc_localised_key(method, PASSWORD, RFC_ENGINE)
    expected = hmac.new(localised, data, method).digest()[: vector["length"]]

    plugin = auth.create(method)
    result = plugin.authenticate_outgoing_message(PASSWORD, data, RFC_ENGINE)

    assert auth.digest_length(plugin) == vector["length"]
    assert result == bytes.fromhex(vector["mac"])
    assert result == expected


@pytest.mark.parametrize("method, length", [("md5", 12), ("sha1", 12)])
def test_rfc3414_digest_length(method, length):
    """
    Ensure the RFC 3414 protocols keep their 12 octet digest.
    """
    plugin = auth.create(method)
    digest = plugin.authenticate_outgoing_message(b"key", b"data", b"engine")
    assert auth.digest_length(plugin) == length
    assert len(digest) == length


def test_digest_length_defaults_to_rfc3414():
    """
    Ensure third-party plugins without DIGEST_LENGTH keep 12 octets.
    """
    assert auth.digest_length(SimpleNamespace()) == 12


@pytest.mark.parametrize("method", METHODS)
def test_round_trip(method):
    """
    Ensure an authenticated message carries a digest of the RFC 7860 length
    and is accepted by the receiving side.
    """
    message = make_response(method)
    auth_params = message[usm.locate_auth_params(message)]

    pdu = make_mpm().decode(
        message, V3(USER, Auth(b"authpassword", method), None)
    )

    assert len(auth_params) == PYSNMP_VECTORS[method]["length"]
    assert auth_params != b"\x00" * len(auth_params)
    assert isinstance(pdu, GetResponse)
    assert pdu.value.varbinds[0].value.pythonize() == b"the-description"


@pytest.mark.parametrize("method", METHODS)
def test_round_trip_without_received_bytes(method):
    """
    Ensure verification over a re-encoded message also uses the length of
    the received digest.
    """
    message = make_response(method)
    decoded = Message.decode(message)
    secparams = usm.USMSecurityParameters.decode(decoded.security_parameters)

    usm.verify_authentication(
        decoded, V3(USER, Auth(b"authpassword", method), None), secparams
    )


@pytest.mark.parametrize("method", METHODS)
def test_tampered_message_is_rejected(method):
    """
    Ensure a message modified after signing is rejected.
    """
    message = make_response(method)
    offset = message.index(b"the-description")
    tampered = message[:offset] + b"T" + message[offset + 1 :]

    with pytest.raises(usm.AuthenticationError):
        make_mpm().decode(
            tampered, V3(USER, Auth(b"authpassword", method), None)
        )


@pytest.mark.parametrize("method", METHODS)
def test_wrong_method_is_rejected(method):
    """
    Ensure a message signed with an RFC 7860 method is not accepted with a
    different method using the same password.
    """
    message = make_response(method)
    other = "sha256" if method != "sha256" else "sha1"

    with pytest.raises(usm.AuthenticationError):
        make_mpm().decode(message, V3(USER, Auth(b"authpassword", other), None))


@pytest.mark.parametrize("method", METHODS)
def test_truncated_digest_is_rejected(method):
    """
    Ensure a digest truncated to the RFC 3414 length is rejected.
    """
    plugin = auth.create(method)
    data = b"some-message"
    digest = plugin.authenticate_outgoing_message(PASSWORD, data, ENGINE)

    assert not plugin.authenticate_incoming_message(
        PASSWORD, data, digest[:12], ENGINE
    )


@pytest.mark.parametrize("method", METHODS + ["md5", "sha1"])
def test_wrong_digest_length_is_rejected(method):
    """
    Ensure a digest that does not have the length of the authentication
    method is rejected before the digest is computed.
    """
    message = Message.decode(make_response(method))
    secparams = usm.USMSecurityParameters.decode(message.security_parameters)
    shortened = replace(secparams, auth_params=secparams.auth_params[:-1])

    with pytest.raises(usm.AuthenticationError, match="digest length"):
        usm.verify_authentication(
            message, V3(USER, Auth(b"authpassword", method), None), shortened
        )
