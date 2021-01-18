from unittest.mock import patch

import pytest

import puresnmp.priv.des as des
from puresnmp.exc import SnmpError


def test_salt_overflow():
    """
    Salts should cycle back to 0 at 0xFFFFFFFF
    """
    with patch("puresnmp.priv.des.randint", return_value=0xFFFFFFFF - 1):
        pot = des.reference_saltpot()
        result = [next(pot), next(pot), next(pot)]
        expected = [0xFFFFFFFF - 1, 0, 1]
    assert result == expected


def test_decrypt_invalid_data():
    """
    Trying to decrypt data with invalid length should raise
    """
    with pytest.raises(SnmpError) as exc:
        des.decrypt_data(b"key", b"invalid-data", b"engine-id", b"salt")
    exc.match("multiple of 8")
