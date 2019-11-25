import pytest

from puresnmp.api.raw import bulkget
from puresnmp.test import readbytes
from puresnmp.x690.types import Integer, OctetString

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch  # type: ignore


def test_54_endofmibview():
    """
    The dump in ``gh-issues/54-endofmibview.hex`` contains an "endOfMibView"
    marker on the OID '1.3.6.1.6.3.10.2.1.4.0'. So that should be the last OID
    we see.


    NOTE: The return-value of ``bulkget`` for listings is a dictionary which
    cannot represent the ``endOfMibView`` marker as-is as it would require to
    add the OID twice. For the "pythonic" API this is always correct as it is
    supposed to hide the SNMP internals. If is debatable whether this behaviour
    is wanted in the "raw" API though. For now this is not supported as it
    would require a non backwards-compatible change in the API (the data-type
    would change). Using something that "behaves like" a dict is also
    questionable acceptable as it would be non-deterministic what happens when
    accessing the key which caused the ``endOfMibView`` as this is the one that
    is duplicated.
    """
    data = readbytes('gh-issues/54-endofmibview.hex')
    with patch('puresnmp.api.raw.Transport') as ptch:
        ptch().send.return_value = data
        ptch().get_request_id.return_value = 123
        result = bulkget('192.0.2.1', 'private', [], ['1.2.3'],
                 max_list_size=10)
    assert result.scalars == {}

    expected_lists = {
        '1.3.6.1.4.1.12325.1.303.1.9.1.3.1.0': OctetString(b'\x00'*404),
        '1.3.6.1.4.1.12325.1.303.1.9.1.3.2.0': OctetString(b'\x00'*404),
        '1.3.6.1.6.3.1.1.6.1.0': Integer(1103779487),
        '1.3.6.1.6.3.10.2.1.1.0': OctetString(b'\x80\x00\x08\xbe\x803740773355'),
        '1.3.6.1.6.3.10.2.1.2.0': Integer(1),
        '1.3.6.1.6.3.10.2.1.3.0': Integer(632),
        '1.3.6.1.6.3.10.2.1.4.0': Integer(1500)
        # TODO verify if this should be true  "1.3.6.1.6.3.10.2.1.4.0": EndOfMibView(),
    }
    assert result.listing == expected_lists
