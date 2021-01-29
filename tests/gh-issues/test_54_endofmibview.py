from unittest.mock import patch

import pytest
from x690.types import Integer, ObjectIdentifier, OctetString

from puresnmp.credentials import V2C
from tests import readbytes

OID = ObjectIdentifier


@pytest.mark.asyncio
async def test_54_endofmibview(mocked_raw):
    data = readbytes("gh-issues/54-endofmibview.hex")
    mocked_raw.sender.set_values([data])
    mocked_raw.credentials = V2C("public")
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 1540273572
        result = await mocked_raw.bulkget([], [OID("1.2.3")], max_list_size=10)
    assert result.scalars == {}

    expected_lists = {
        OID("1.3.6.1.4.1.12325.1.303.1.9.1.3.1.0"): OctetString(b"\x00" * 404),
        OID("1.3.6.1.4.1.12325.1.303.1.9.1.3.2.0"): OctetString(b"\x00" * 404),
        OID("1.3.6.1.6.3.1.1.6.1.0"): Integer(1103779487),
        OID("1.3.6.1.6.3.10.2.1.1.0"): OctetString(
            b"\x80\x00\x08\xbe\x803740773355"
        ),
        OID("1.3.6.1.6.3.10.2.1.2.0"): Integer(1),
        OID("1.3.6.1.6.3.10.2.1.3.0"): Integer(632),
        OID("1.3.6.1.6.3.10.2.1.4.0"): Integer(1500),
    }
    assert result.listing == expected_lists
