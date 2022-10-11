from unittest.mock import Mock

import pytest

import puresnmp.plugins.security as security
from puresnmp.exc import UnknownSecurityModel


def test_validity_check() -> None:
    """
    Ensure that the validity check for security-plugins returns the proper
    boolean
    """
    mock = Mock(spec=("create", "IDENTIFIER"))
    result = security.is_valid_sec_plugin(mock)
    assert result == True


def test_create_known() -> None:
    result = security.create(2, {})
    import puresnmp_plugins.security.v2c

    assert isinstance(
        result, puresnmp_plugins.security.v2c.SNMPv2cSecurityModel
    )


def test_create_unknown() -> None:
    with pytest.raises(UnknownSecurityModel):
        security.create(42, {})
