# pylint: skip-file

"""
Test the "external" interface.

The "external" interface is what the user sees. It should be pythonic and easy
to use.
"""
import asyncio
from ipaddress import ip_address
from typing import Any
from unittest.mock import Mock

try:
    from unittest.mock import AsyncMock
except ImportError:
    from asyncmock import AsyncMock

import pytest
from x690.types import Integer, ObjectIdentifier, OctetString

from puresnmp import PyWrapper
from puresnmp.api.raw import Client
from puresnmp.pdu import VarBind
from puresnmp.types import Counter, Gauge, IpAddress
from puresnmp.util import BulkResult
from puresnmp.varbind import PyVarBind

from .conftest import AsyncIter

OID = ObjectIdentifier


def async_result(data: Any) -> asyncio.Future:
    future: asyncio.Future = asyncio.Future()
    future.set_result(data)
    return future


@pytest.mark.asyncio
async def test_get_string():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)

    expected = (
        b"Linux d24cf7f36138 4.4.0-28-generic #47-Ubuntu SMP "
        b"Fri Jun 24 10:09:13 UTC 2016 x86_64"
    )
    raw_client.get = AsyncMock(
        return_value=OctetString(
            b"Linux d24cf7f36138 4.4.0-28-generic #47-Ubuntu SMP "
            b"Fri Jun 24 10:09:13 UTC 2016 x86_64"
        )
    )
    result = await client.get("1.2.3")
    assert result == expected


@pytest.mark.asyncio
async def test_get_oid():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)
    expected = "1.3.6.1.4.1.8072.3.2.10"
    raw_client.get = AsyncMock(
        return_value=ObjectIdentifier("1.3.6.1.4.1.8072.3.2.10")
    )
    result = await client.get("1.2.3")
    assert result == expected


@pytest.mark.asyncio
async def test_set_string():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)
    expected = b"foo"
    raw_client.multiset = AsyncMock(
        return_value={ObjectIdentifier("1.2.3"): OctetString(b"foo")}
    )
    result = await client.set("1.2.3", OctetString(b"foo"))
    assert result == expected


@pytest.mark.asyncio
async def test_set_string_absolute():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)
    expected = b"foo"
    raw_client.multiset = AsyncMock(
        return_value={ObjectIdentifier("1.2.3"): OctetString(b"foo")}
    )
    result = await client.set(".1.2.3", OctetString(b"foo"))
    assert result == expected


@pytest.mark.asyncio
async def test_walk():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)

    expected = [
        VarBind("1.3.6.1.2.1.2.2.1.5.1", 10000000),
        VarBind("1.3.6.1.2.1.2.2.1.5.13", 4294967295),
    ]

    raw_client.walk.return_value = AsyncIter(
        [
            VarBind(
                ObjectIdentifier("1.3.6.1.2.1.2.2.1.5.1"),
                Gauge(10000000),
            ),
            VarBind(
                ObjectIdentifier("1.3.6.1.2.1.2.2.1.5.13"),
                Integer(4294967295),
            ),
        ]
    )
    result = []
    async for row in client.walk("1.3.6.1.2.1.2.2.1.5"):
        result.append(row)
    assert result == expected


@pytest.mark.asyncio
async def test_multiget():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)
    expected = [
        "1.3.6.1.4.1.8072.3.2.10",
        b"Linux 7fbf2f0c363d 4.4.0-28-generic #47-Ubuntu SMP Fri "
        b"Jun 24 10:09:13 UTC 2016 x86_64",
    ]
    raw_client.multiget = AsyncMock(
        return_value=[
            ObjectIdentifier("1.3.6.1.4.1.8072.3.2.10"),
            OctetString(
                b"Linux 7fbf2f0c363d 4.4.0-28-generic "
                b"#47-Ubuntu SMP Fri Jun 24 10:09:13 "
                b"UTC 2016 x86_64"
            ),
        ]
    )
    result = await client.multiget(
        [
            "1.3.6.1.2.1.1.2.0",
            "1.3.6.1.2.1.1.1.0",
        ]
    )
    assert result == expected


@pytest.mark.asyncio
async def test_multi_walk():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)
    expected = [
        VarBind("1.3.6.1.2.1.2.2.1.1.1", 1),
        VarBind("1.3.6.1.2.1.2.2.1.2.1", b"lo"),
        VarBind("1.3.6.1.2.1.2.2.1.1.78", 78),
        VarBind("1.3.6.1.2.1.2.2.1.2.78", b"eth0"),
    ]

    raw_client.multiwalk.return_value = AsyncIter(
        [
            VarBind(
                ObjectIdentifier("1.3.6.1.2.1.2.2.1.1.1"),
                Integer(1),
            ),
            VarBind(
                ObjectIdentifier("1.3.6.1.2.1.2.2.1.2.1"),
                OctetString(b"lo"),
            ),
            VarBind(
                ObjectIdentifier("1.3.6.1.2.1.2.2.1.1.78"),
                Integer(78),
            ),
            VarBind(
                ObjectIdentifier("1.3.6.1.2.1.2.2.1.2.78"),
                OctetString(b"eth0"),
            ),
        ]
    )
    result = []
    async for row in client.multiwalk(
        ["1.3.6.1.2.1.2.2.1.1", "1.3.6.1.2.1.2.2.1.2"],
    ):
        result.append(row)
    assert result == expected


@pytest.mark.asyncio
async def test_multiset():
    """
    Test setting multiple OIDs at once.

    NOTE: The OID '1.3.6.1.2.1.1.5.0' below is manually edited for
            unit-testing. It probably has a different type in the real world!
    """
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)
    raw_client.multiset = AsyncMock(
        return_value={
            "1.3.6.1.2.1.1.4.0": OctetString(b"hello@world.com"),
            "1.3.6.1.2.1.1.5.0": OctetString(b"hello@world.com"),
        }
    )

    result = await client.multiset(
        {
            "1.3.6.1.2.1.1.4.0": OctetString(b"hello@world.com"),
            "1.3.6.1.2.1.1.5.0": OctetString(b"hello@world.com"),
        },
    )
    expected = {
        "1.3.6.1.2.1.1.4.0": b"hello@world.com",
        "1.3.6.1.2.1.1.5.0": b"hello@world.com",
    }
    assert result == expected


@pytest.mark.asyncio
async def test_multiset_absolute():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)
    raw_client.multiset = AsyncMock(
        return_value={
            "1.3.6.1.2.1.1.4.0": OctetString(b"hello@world.com"),
            "1.3.6.1.2.1.1.5.0": OctetString(b"hello@world.com"),
        }
    )
    result = await client.multiset(
        {
            ".1.3.6.1.2.1.1.4.0": OctetString(b"hello@world.com"),
            ".1.3.6.1.2.1.1.5.0": OctetString(b"hello@world.com"),
        },
    )
    expected = {
        "1.3.6.1.2.1.1.4.0": b"hello@world.com",
        "1.3.6.1.2.1.1.5.0": b"hello@world.com",
    }
    assert result == expected


@pytest.mark.asyncio
async def test_getnext():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)

    expected = VarBind("1.3.6.1.6.3.1.1.6.1.0", 354522558)

    raw_client.getnext = AsyncMock(
        return_value=VarBind(
            ObjectIdentifier("1.3.6.1.6.3.1.1.6.1.0"),
            Integer(354522558),
        )
    )
    result = await client.getnext("1.3.6.1.5")
    assert result == expected


@pytest.mark.asyncio
async def test_bulkget():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)

    expected = BulkResult(
        {
            "1.3.6.1.2.1.1.1.0": b"Linux 7e68e60fe303 4.4.0-28-generic "
            b"#47-Ubuntu SMP Fri Jun 24 10:09:13 UTC 2016 x86_64"
        },
        {
            "1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1": 10,
            "1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1": b"\x02B\xe2\xc5\x8d\t",
            "1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1": ip_address("172.17.0.1"),
            "1.3.6.1.2.1.4.1.0": 1,
            "1.3.6.1.2.1.4.3.0": 57,
        },
    )

    raw_client.bulkget = AsyncMock(
        return_value=BulkResult(
            {
                "1.3.6.1.2.1.1.1.0": OctetString(
                    b"Linux 7e68e60fe303 4.4.0-28-generic "
                    b"#47-Ubuntu SMP Fri Jun 24 10:09:13 UTC 2016 x86_64"
                )
            },
            {
                "1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1": Integer(10),
                "1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1": OctetString(
                    b"\x02B\xe2\xc5\x8d\t"
                ),
                "1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1": IpAddress(
                    ip_address("172.17.0.1")
                ),
                "1.3.6.1.2.1.4.1.0": Integer(1),
                "1.3.6.1.2.1.4.3.0": Counter(57),
            },
        )
    )
    result = await client.bulkget(
        ["1.3.6.1.2.1.1.1"],
        ["1.3.6.1.2.1.3.1"],
        max_list_size=5,
    )
    assert result == expected


@pytest.mark.asyncio
async def test_bulkwalk():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)
    raw_client.bulkwalk.return_value = AsyncIter(
        [
            VarBind(OID("1.3.6.1.2.1.2.2.1.1.1"), Integer(1)),
            VarBind(OID("1.3.6.1.2.1.2.2.1.1.10"), Integer(10)),
            VarBind(OID("1.3.6.1.2.1.2.2.1.2.1"), OctetString(b"lo")),
            VarBind(OID("1.3.6.1.2.1.2.2.1.22.10"), ObjectIdentifier("0.0")),
        ]
    )

    result = []
    async for row in client.bulkwalk(["1.3.6.1.2.1.2.2"], bulk_size=20):
        result.append(row)

    expected = [
        PyVarBind("1.3.6.1.2.1.2.2.1.1.1", 1),
        PyVarBind("1.3.6.1.2.1.2.2.1.1.10", 10),
        PyVarBind("1.3.6.1.2.1.2.2.1.2.1", b"lo"),
        PyVarBind("1.3.6.1.2.1.2.2.1.22.10", "0.0"),
    ]

    assert result == expected


@pytest.mark.asyncio
async def test_table():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)
    raw_client.table = AsyncMock(
        return_value=[
            {"0": "1", "1": Integer(1)},
            {"0": "2", "1": Integer(2)},
        ]
    )
    result = []
    for row in await client.table("1.2"):
        result.append(row)
    expected = [
        {"0": "1", "1": 1},
        {"0": "2", "1": 2},
    ]
    assert result == expected


@pytest.mark.asyncio
async def test_bulktable():
    raw_client = Mock(spec=Client)
    client = PyWrapper(client=raw_client)
    raw_client.bulktable = AsyncMock(
        return_value=[
            {"0": "1", "1": Integer(1)},
            {"0": "2", "1": Integer(2)},
        ]
    )
    result = await client.bulktable("1.2")
    expected = [
        {"0": "1", "1": 1},
        {"0": "2", "1": 2},
    ]
    assert result == expected
