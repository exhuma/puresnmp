"""
This module contains test to ensure that the public API of *puresnmp* does
not accidentally change.
"""
from ipaddress import ip_address
from unittest.mock import MagicMock

import pytest
from x690.types import OctetString

from puresnmp import RawClient
from puresnmp.credentials import V2C

from .. import readbytes_multiple


def test_client():
    """
    Ensure that the client has the necessary information available
    """
    raise pytest.skip("TODO")
    client = RawClient("192.0.2.1", V2C("mycommunity"), send)
    assert client.ip == ip_address("192.0.2.1")
    assert client.default_credentials == V2C("mycommunity")
    assert isinstance(client.transport, Transport)
    assert client.transport.retries == 3
    assert client.transport.timeout == 2


@pytest.mark.parametrize(
    "method, args, kwargs, response_data",
    [
        (
            "bulkget",
            (["1.2.3", "2.3.4"], ["3.4.5", "4.5.6"]),
            dict(max_list_size=10),
            "apiv1/bulkget_response.hex",
        ),
        (
            "bulkwalk",
            (["1.2.3", "2.3.4"],),
            dict(bulk_size=10),
            "apiv1/bulkwalk_response.hex",
        ),
        ("get", ("1.2.3",), dict(), "apiv1/get_response.hex"),
        (
            "getnext",
            ("1.3.6.1.2.1.1.3.1.0",),
            dict(),
            "apiv1/getnext_response.hex",
        ),
        ("multiget", (["1.2.3", "2.3.4"],), {}, "apiv1/multiget_response.hex"),
        (
            "multigetnext",
            (["1.2.3", "1.3.6.1.2.1.3.1.0"],),
            {},
            "apiv1/multigetnext_response.hex",
        ),
        (
            "multiset",
            (
                {
                    "1.3.6.1.2.1.1.4.0": OctetString(b"foo"),
                    "1.3.6.1.2.1.1.6.0": OctetString(b"bar"),
                },
            ),
            {},
            "apiv1/multiset_response.hex",
        ),
        (
            "multiwalk",
            (["1.2.3", "2.3.4"],),
            {},
            "apiv1/multiwalk_response.hex",
        ),
        (
            "set",
            (
                "1.3.6.1.2.1.1.6.0",
                OctetString(b"hello"),
            ),
            {},
            "apiv1/set_response.hex",
        ),
        (
            "table",
            ("1.2.3",),
            dict(num_base_nodes=2),
            "apiv1/table_response.hex",
        ),
        ("walk", ("1.2.3",), dict(), "apiv1/walk_response.hex"),
    ],
)
def test_signatures(method, args, kwargs, response_data):
    raise pytest.skip("TODO async")
    kwarg_overrides = dict(timeout=10)
    response_data = readbytes_multiple(response_data)
    transport = MagicMock()
    transport.get_request_id.return_value = 0
    transport.send.side_effect = response_data

    # V2 with community
    client = RawClient("192.0.2.1", V2C("overridden_community"), transport)
    func = getattr(client, method)
    func(*args, **{**kwargs, **kwarg_overrides})
