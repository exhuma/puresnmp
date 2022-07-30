from unittest.mock import Mock

import pytest

import puresnmp.plugins.mpm as mpm
from puresnmp.exc import UnknownMessageProcessingModel


async def fake_sender(data: bytes) -> bytes:
    return b""


def test_validity_check() -> None:
    """
    Ensure that the validity check for mpm-plugins returns the proper boolean
    """
    mock = Mock(spec=("create", "IDENTIFIER"))
    result = mpm.is_valid_mpm_plugin(mock)
    assert result == True


def test_create_known() -> None:
    result = mpm.create(1, fake_sender, {})
    import puresnmp_plugins.mpm.v2c

    assert isinstance(result, puresnmp_plugins.mpm.v2c.V2CMPM)


def test_create_unknown() -> None:
    with pytest.raises(UnknownMessageProcessingModel):
        mpm.create(42, fake_sender, {})
