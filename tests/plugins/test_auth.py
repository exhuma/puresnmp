from unittest.mock import Mock

import pytest

import puresnmp.plugins.auth as auth
from puresnmp.exc import UnknownAuthModel


def test_validity_check():
    """
    Ensure that the validity check for auth-plugins returns the proper boolean
    """
    mock = Mock(
        spec=(
            "authenticate_incoming_message",
            "authenticate_outgoing_message",
            "IDENTIFIER",
            "IANA_ID",
        )
    )
    result = auth.is_valid_auth_mod(mock)
    assert result == True


def test_create_known():
    result = auth.create("md5")
    import puresnmp_plugins.auth.md5

    assert result == puresnmp_plugins.auth.md5


def test_create_unknown():
    with pytest.raises(UnknownAuthModel):
        auth.create("unknown")


@pytest.mark.parametrize("method", ["md5", "sha1"])
def test_incoming_digest(method):
    """
    Incoming messages are only authentic if the digest matches exactly
    """
    plugin = auth.create(method)
    key, data, engine_id = b"authkey", b"message", b"engine-id"
    digest = plugin.authenticate_outgoing_message(key, data, engine_id)
    tampered = bytes([digest[0] ^ 1]) + digest[1:]
    assert plugin.authenticate_incoming_message(key, data, digest, engine_id)
    assert not plugin.authenticate_incoming_message(
        key, data, tampered, engine_id
    )
    assert not plugin.authenticate_incoming_message(
        key, data, digest[:-1], engine_id
    )
