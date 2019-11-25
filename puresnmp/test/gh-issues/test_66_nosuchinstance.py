# type: ignore
"""
When an SNMP agent returns the type-value 0x81 a NULL value should be reported.

By definition in RFC-1905 the "value" part in a VarBind can either be a value,
or one of:

    "noSuchObject": the requested OID does not exist
    "noSuchInstance": the OID exists but has no value
    "endOfMibView": A marker to signify we have seen all that we are allowed to
        see in an operation based on "get-next".

This is (at the time of this writing, 2019-10-10) not handled properly. See
also gihub issue #54. This module defines a test verifyng that we get a correct
value from a noSuchInstance marker.
"""
from puresnmp.api.pythonic import multiget as pyget
from puresnmp.api.raw import multiget
from puresnmp.test import readbytes
from puresnmp.types import NoSuchInstance
from puresnmp.x690.types import Integer

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch


def test_data_type():
    """
    We want to have a special data-type for noSuchInstance which behaves
    properly (like a varbind & implicit null).
    """
    value = NoSuchInstance('1.2.3.4.5')
    assert bool(value) is False
    assert value.oid == '1.2.3.4.5'
    assert value.value is None


def test_66_nosuchinstance_raw():
    """
    If we get a noSuchInstance VarBind, we want to report this as an
    appropriate value.
    """
    data = readbytes('gh-issues/66-nosuchinstance.hex')
    with patch('puresnmp.api.raw.Transport') as ptch:
        ptch().send.return_value = data
        ptch().get_request_id.return_value = 123
        result = multiget('192.0.2.1', 'private', ['1.2.3', '2.3.4'])
    assert result == [Integer(1), NoSuchInstance('1.2.3')]


def test_66_nosuchinstance_pythonic():
    """
    Pure Python has no data-type to represent the same concept as
    "noSuchInstance" so we generalise it as ``None``
    """
    data = readbytes('gh-issues/66-nosuchinstance.hex')
    with patch('puresnmp.api.raw.Transport') as ptch:
        ptch().send.return_value = data
        ptch().get_request_id.return_value = 123
        result = pyget('192.0.2.1', 'private', ['1.2.3', '2.3.4'])
    assert result == [1, None]
