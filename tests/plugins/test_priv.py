from unittest.mock import Mock

import pytest

import puresnmp.plugins.priv as priv
from puresnmp.exc import UnknownPrivacyModel


def test_validity_check() -> None:
    """
    Ensure that the validity check for priv-plugins returns the proper
    boolean
    """
    mock = Mock(spec=("encrypt_data", "decrypt_data", "IDENTIFIER", "IANA_ID"))
    result = priv.is_valid_priv_mod(mock)
    assert result == True


def test_create_unknown() -> None:
    with pytest.raises(UnknownPrivacyModel):
        priv.create(42)
