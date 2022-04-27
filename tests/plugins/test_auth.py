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
