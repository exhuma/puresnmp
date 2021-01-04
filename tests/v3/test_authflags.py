"""
Test support for auth-flags
"""
import pytest
from x690.types import OctetString

from puresnmp.messageprocessing import V3Flags


@pytest.mark.parametrize(
    "bytevalue, expected",
    [
        (b"\x04", V3Flags(auth=False, priv=False, reportable=True)),
        (b"\x05", V3Flags(auth=True, priv=False, reportable=True)),
        (b"\x07", V3Flags(auth=True, priv=True, reportable=True)),
    ],
)
def test_authflags(bytevalue, expected):
    """
    We should be correctly decoding the message auth/priv flags from bytes
    """
    snmp_value = OctetString(bytevalue)
    result = V3Flags.decode(snmp_value)
    assert result == expected
