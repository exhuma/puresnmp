# pylint: skip-file
"""
Test the external "raw" interface.

"raw" means that types are not converted to pythonic types but are returned as
PureSNMP object instances.
"""


import unittest
from logging import WARNING, getLogger
from unittest.mock import call, patch

import pytest
from x690.types import Integer, Null, ObjectIdentifier, OctetString, Sequence

from puresnmp.api.raw import RawClient, traps
from puresnmp.const import Version
from puresnmp.credentials import V2C
from puresnmp.exc import FaultySNMPImplementation, NoSuchOID, SnmpError
from puresnmp.pdu import (
    BulkGetRequest,
    GetNextRequest,
    GetResponse,
    VarBind,
)
from puresnmp.transport import SocketResponse
from puresnmp.types import Counter, Gauge, IpAddress, TimeTicks
from puresnmp.typevars import SocketInfo
from puresnmp.util import BulkResult

from . import CapturingHandler, readbytes, readbytes_multiple
from .conftest import AsyncIter


@pytest.mark.asyncio
async def test_get_string(mocked_send):
    data = readbytes("get_sysdescr_01.hex")
    mocked_send.sender.set_values([data])
    expected = OctetString(
        b"Linux d24cf7f36138 4.4.0-28-generic #47-Ubuntu SMP "
        b"Fri Jun 24 10:09:13 UTC 2016 x86_64"
    )
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 3262242864
        result = await mocked_send.get("1.2.3")
    assert result == expected


@pytest.mark.asyncio
async def test_get_oid(mocked_send):
    data = readbytes("get_sysoid_01.hex")
    mocked_send.sender.set_values([data])
    expected = ObjectIdentifier.from_string("1.3.6.1.4.1.8072.3.2.10")
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 1401558560
        result = await mocked_send.get("1.2.3")
    assert result == expected


@pytest.mark.asyncio
async def test_get_multiple_return_binds(mocked_send):
    """
    A "GET" response should only return one varbind.
    """
    data = readbytes("get_sysoid_01_error.hex")
    mocked_send.sender.set_values([data])
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 123
        with pytest.raises(SnmpError) as exc:
            await mocked_send.get("1.2.3")
        exc.match(r"varbind")


@pytest.mark.asyncio
async def test_get_non_existing_oid(mocked_send):
    """
    A "GET" response on a non-existing OID should raise an appropriate
    exception.
    """
    raise pytest.skip("TODO")
    data = readbytes("get_non_existing.hex")
    mocked_send.sender.set_values([data])
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = -1
        with pytest.raises(NoSuchOID):
            await mocked_send.get("1.2.3")


@pytest.mark.asyncio
async def test_walk(mocked_send):
    response_1 = readbytes("walk_response_1.hex")
    response_2 = readbytes("walk_response_2.hex")
    response_3 = readbytes("walk_response_3.hex")
    mocked_send.sender.set_values([response_1, response_2, response_3])

    expected = [
        VarBind(
            ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.5.1"),
            Gauge(10000000),
        ),
        VarBind(
            ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.5.13"),
            Gauge(4294967295),
        ),
    ]

    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.side_effect = [463373299, 463373300, 463373301]
        result = []
        async for row in mocked_send.walk("1.3.6.1.2.1.2.2.1.5"):
            result.append(row)
    assert result == expected


@pytest.mark.asyncio
async def test_walk_multiple_return_binds(mocked_send):
    """
    A "WALK" response should only return one varbind.
    """
    data = readbytes("get_sysoid_01_error.hex")
    mocked_send.sender.set_values([data])
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 123
        with pytest.raises(SnmpError) as exc:
            async for _ in mocked_send.walk("1.2.3"):
                pass
        exc.match(r"varbind")


@pytest.mark.asyncio
async def test_multiget(mocked_send):
    data = readbytes("multiget_response.hex")
    mocked_send.sender.set_values([data])
    expected = [
        ObjectIdentifier.from_string("1.3.6.1.4.1.8072.3.2.10"),
        OctetString(
            b"Linux 7fbf2f0c363d 4.4.0-28-generic "
            b"#47-Ubuntu SMP Fri Jun 24 10:09:13 "
            b"UTC 2016 x86_64"
        ),
    ]
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 1913359423
        result = await mocked_send.multiget(
            ["1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.1.0"]
        )
    assert result == expected


@pytest.mark.asyncio
async def test_multi_walk(mocked_send):
    response_1 = readbytes("multiwalk_response_1.hex")
    response_2 = readbytes("multiwalk_response_2.hex")
    response_3 = readbytes("multiwalk_response_3.hex")

    expected = [
        VarBind(
            ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.1.1"),
            Integer(1),
        ),
        VarBind(
            ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.2.1"),
            OctetString(b"lo"),
        ),
        VarBind(
            ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.1.78"),
            Integer(78),
        ),
        VarBind(
            ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.2.78"),
            OctetString(b"eth0"),
        ),
    ]

    mocked_send.sender.set_values([response_1, response_2, response_3])
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 1474004155
        result = []
        async for row in mocked_send.multiwalk(
            ["1.3.6.1.2.1.2.2.1.1", "1.3.6.1.2.1.2.2.1.2"],
        ):
            result.append(row)
    assert result == expected


@pytest.mark.asyncio
async def test_multiwalk_non_containment(mocked_send):
    """
    Running a multiwalk should raise an exception if the agent returns OIDs
    which are not properly increasing.

    First case: Returned OIDs are the same
    """
    OID = ObjectIdentifier.from_string

    response = Sequence(
        Integer(1),
        OctetString(b"public"),
        GetResponse(
            123,
            [
                VarBind(oid=OID("1.2.3"), value=Integer(30)),
                VarBind(oid=OID("2.3.4"), value=Integer(40)),
            ],
        ),
    )
    mocked_send.sender.set_values([bytes(response)])
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 123
        with pytest.raises(FaultySNMPImplementation):
            async for _ in mocked_send.multiwalk(["1.2.3", "2.3.4"]):
                pass


@pytest.mark.asyncio
async def test_multiwalk_non_containment_2(mocked_send):
    """
    Running a multiwalk should raise an exception if the agent returns OIDs
    which are not properly increasing.

    Second case: Returned OIDs are smaller
    """
    OID = ObjectIdentifier.from_string
    response = Sequence(
        Integer(1),
        OctetString(b"public"),
        GetResponse(
            123,
            [
                VarBind(oid=OID("1.2.2"), value=Integer(30)),
                VarBind(oid=OID("2.3.3"), value=Integer(40)),
            ],
        ),
    )
    mocked_send.sender.set_values([bytes(response)])
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 123
        with pytest.raises(FaultySNMPImplementation):
            async for _ in mocked_send.multiwalk(["1.2.3", "2.3.4"]):
                pass


def test_eom(self):
    """
    A test for a walk operation which runs into the endOfMibView marker
    """

    data_generator = readbytes_multiple("x690/multiwalk_endofmibview.hex")

    with patch("puresnmp.api.raw.Transport") as mck, patch(
        "puresnmp.api.raw.get_request_id"
    ) as gri:
        mck().send.side_effect = data_generator
        gri.return_value = 0
        client = RawClient("::1", V2C("public"))
        result = client.multiwalk(
            [
                "1.3.6.1.6.3.16.1.5.2.1.6.6.95.110.111.110.101.95.1",
            ],
        )
        result = list(result)

    OID = ObjectIdentifier.from_string
    root = "1.3.6.1.6.3.16.1.5.2.1.6.6.95.110.111.110.101.95.1."
    expected = [
        VarBind(OID(root + "0"), Integer(1)),
        VarBind(OID(root + "1"), Integer(1)),
        VarBind(OID(root + "2"), Integer(1)),
    ]

    self.assertEqual(result, expected)


@pytest.mark.asyncio
async def test_multiset(mocked_send):
    """
    Test setting multiple OIDs at once.

    NOTE: The OID '1.3.6.1.2.1.1.5.0' below is manually edited for
            unit-testing. It probably has a different type in the real world!
    """
    data = readbytes("multiset_response.hex")
    mocked_send.sender.set_values([data])
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 0
        result = await mocked_send.multiset(
            {
                "1.3.6.1.2.1.1.4.0": OctetString(b"hello@world.com"),
                "1.3.6.1.2.1.1.5.0": OctetString(b"hello@world.com"),
            },
        )
    expected = {
        "1.3.6.1.2.1.1.4.0": OctetString(b"hello@world.com"),
        "1.3.6.1.2.1.1.5.0": OctetString(b"hello@world.com"),
    }
    assert result == expected


@pytest.mark.asyncio
async def test_get_call_args(mocked_send):
    data = readbytes("dummy.hex")  # any dump would do
    mocked_send.sender.set_values([data])
    packet = Sequence(
        Integer(Version.V2C),
        OctetString("public"),
        GetNextRequest(0, VarBind(ObjectIdentifier(1, 2, 3), Null())),
    )
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 0
        await mocked_send.getnext("1.2.3")
        assert mocked_send.sender.mock_calls == [call(-1, bytes(packet))]


@pytest.mark.asyncio
async def test_getnext(mocked_send):
    data = readbytes("getnext_response.hex")
    mocked_send.sender.set_values([data])
    expected = VarBind("1.3.6.1.6.3.1.1.6.1.0", Integer(354522558))

    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 2089242883
        result = await mocked_send.getnext("1.3.6.1.5")
    assert result == expected


@pytest.mark.asyncio
async def test_getnext_increasing_oid_strict(mocked_send):
    """
    When running "getnext" we expect a different OID than the one we passed
    in. If not, this can cause endless-loops in the worst case. Faulty SNMP
    implementations may behave this way!
    """
    raise pytest.skip("TODO")
    requested_oid = ObjectIdentifier(1, 2, 3, 4)
    response_object = Sequence(
        Integer(1),
        OctetString(b"public"),
        GetResponse(234, [VarBind(requested_oid, Integer(123))]),
    )
    response_bytes = bytes(response_object)
    mocked_send.sender.set_values(response_bytes)

    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 0
        with pytest.raises(FaultySNMPImplementation):
            await mocked_send.getnext("1.2.3.4")


@pytest.mark.asyncio
async def test_walk_increasing_oid_lenient(mocked_send):
    """
    We want to be able to allow faulty SNMP implementations to at least try
    to fetch the values in a walk which are not increasing. It should read
    up to the values which are no longer increasing and emit a warning.
    """
    logger = getLogger("puresnmp")
    handler = CapturingHandler()
    logger.addHandler(handler)

    response_binds = [
        VarBind(ObjectIdentifier(1, 2, 3), Integer(123)),
        VarBind(ObjectIdentifier(1, 2, 4), Integer(124)),
        VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),
        VarBind(ObjectIdentifier(1, 2, 1), Integer(121)),  # non-increasing
    ]
    response_packets = [
        Sequence(Integer(1), OctetString(b"public"), GetResponse(234, [bind]))
        for bind in response_binds
    ]
    response_bytes = [bytes(packet) for packet in response_packets]
    mocked_send.sender.set_values(response_bytes)

    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 234
        result = []
        async for row in mocked_send.walk("1.2", errors="warn"):
            result.append(row)

    # The last OID in the mocked responses is decreasing so we want to read
    # just up to that point.
    expected = [
        VarBind(ObjectIdentifier(1, 2, 3), Integer(123)),
        VarBind(ObjectIdentifier(1, 2, 4), Integer(124)),
        VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),
    ]
    assert result == expected

    # We also want to make sure that we have a proper warning about this
    handler.assertContains(WARNING, r".*1.2.1.*1.2.5.*")
    logger.removeHandler(handler)


@pytest.mark.asyncio
async def test_walk_endless_loop(mocked_send):
    """
    In rare cases, some devices fall into an endless loop by returning the
    requested OID on a "getnext" call during a "walk" operation. A SNMP
    client behaving according to the SNMP spec will fall into an endless
    loop. This test fakes such a case and revents the loop.
    """
    response_binds = [
        VarBind(ObjectIdentifier(1, 2, 3), Integer(123)),
        VarBind(ObjectIdentifier(1, 2, 4), Integer(124)),
        VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),
        VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),  # same OID
        VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),  # same OID
        VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),  # same OID
    ]
    response_packets = [
        Sequence(Integer(1), OctetString(b"public"), GetResponse(234, [bind]))
        for bind in response_binds
    ]
    response_bytes = [bytes(packet) for packet in response_packets]
    mocked_send.sender.set_values(response_bytes)

    handler = CapturingHandler()
    logger = getLogger("puresnmp")
    logger.addHandler(handler)
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 234
        result = []
        async for row in mocked_send.walk("1.2", errors="warn"):
            result.append(row)
    logger.removeHandler(handler)

    # The last OID in the mocked responses is decreasing so we want to read
    # just up to that point.
    expected = [
        VarBind(ObjectIdentifier(1, 2, 3), Integer(123)),
        VarBind(ObjectIdentifier(1, 2, 4), Integer(124)),
        VarBind(ObjectIdentifier(1, 2, 5), Integer(125)),
    ]
    assert result == expected

    # We also want to make sure that we have a proper warning about this
    handler.assertContains(WARNING, r".*1.2.5.*")


@pytest.mark.asyncio
async def test_get_call_args(mocked_send):
    data = readbytes("dummy.hex")  # any dump would do
    mocked_send.sender.set_values([data])
    packet = Sequence(
        Integer(Version.V2C),
        OctetString("private"),
        BulkGetRequest(
            0, 1, 2, ObjectIdentifier(1, 2, 3), ObjectIdentifier(1, 2, 4)
        ),
    )
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 0
        await mocked_send.bulkget(["1.2.3"], ["1.2.4"], max_list_size=2)
    assert mocked_send.sender.mock_calls == [
        call("192.0.2.1", 161, bytes(packet), timeout=6)
    ]
    1 / 0


@pytest.mark.asyncio
async def test_bulkget(mocked_send):
    data = readbytes("bulk_get_response.hex")
    mocked_send.sender.set_values([data])
    expected = BulkResult(
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
                b"\xac\x11\x00\x01"
            ),
            "1.3.6.1.2.1.4.1.0": Integer(1),
            "1.3.6.1.2.1.4.3.0": Counter(57),
        },
    )

    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 1105659629
        result = await mocked_send.bulkget(
            ["1.3.6.1.2.1.1.1"],
            ["1.3.6.1.2.1.3.1"],
            max_list_size=5,
        )
    assert result == expected


@pytest.mark.asyncio
async def test_eom(mocked_send):
    """
    Test a bulg-get operation which runs into the "endOfMibView" marker.
    """
    data = readbytes("x690/bulk_get_eom_response.hex")
    mocked_send.sender.set_values([data])
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 43764201
        result = await mocked_send.bulkget([], ["1.2.4"], max_list_size=10)

    expected_scalars = {}
    assert result.scalars == expected_scalars

    root = "1.3.6.1.6.3.16.1.5.2.1.6.6.95.110.111.110.101.95.1."
    expected_listing = {
        root + "0": Integer(1),
        root + "1": Integer(1),
        root + "2": Integer(1),
    }
    assert result.listing == expected_listing


@pytest.mark.asyncio
async def test_get_call_args(mocked_send):
    data = readbytes("dummy.hex")  # any dump would do
    mocked_send.sender.set_values([data])
    packet = Sequence(
        Integer(Version.V2C),
        OctetString("private"),
        BulkGetRequest(3262242864, 0, 2, ObjectIdentifier(1, 2, 3)),
    )
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 3262242864
        # we need to consume this to trigger the error
        async for _ in mocked_send.bulkwalk(["1.2.3"], bulk_size=2):
            pass
        assert mocked_send.sender.mock_calls == [
            call("192.0.2.1", 161, bytes(packet), timeout=6)
        ]


@pytest.mark.asyncio
async def test_get_call_args_issue_22(mocked_send):
    data = readbytes("dummy.hex")  # any dump would do
    mocked_send.sender.set_values([data])
    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.return_value = 0
        with pytest.raises(TypeError) as exc:
            # we need to consume this to trigger the error
            async for _ in mocked_send.bulkwalk("1.2.3", bulk_size=2):
                pass
        exc.match(r"OIDS.*list")


@pytest.mark.asyncio
async def test_bulkwalk(mocked_send):
    req1 = readbytes("bulkwalk_request_1.hex")
    req2 = readbytes("bulkwalk_request_2.hex")
    req3 = readbytes("bulkwalk_request_3.hex")

    responses = [
        readbytes("bulkwalk_response_1.hex"),
        readbytes("bulkwalk_response_2.hex"),
        readbytes("bulkwalk_response_3.hex"),
    ]
    mocked_send.sender.set_values(responses)

    request_ids = [1001613222, 1001613223, 1001613224]

    with patch("puresnmp.api.raw.get_request_id") as gri:
        gri.side_effect = request_ids
        result = []
        async for row in mocked_send.bulkwalk(
            ["1.3.6.1.2.1.2.2"], bulk_size=20
        ):
            result.append(row)

    assert mocked_send.sender.mock_calls == [
        call("192.0.2.1", 161, req1, timeout=6),
        call("192.0.2.1", 161, req2, timeout=6),
        call("192.0.2.1", 161, req3, timeout=6),
    ]

    expected = [
        VarBind("1.3.6.1.2.1.2.2.1.1.1", Integer(1)),
        VarBind("1.3.6.1.2.1.2.2.1.1.10", Integer(10)),
        VarBind("1.3.6.1.2.1.2.2.1.2.1", OctetString(b"lo")),
        VarBind("1.3.6.1.2.1.2.2.1.2.10", OctetString(b"eth0")),
        VarBind("1.3.6.1.2.1.2.2.1.3.1", Integer(24)),
        VarBind("1.3.6.1.2.1.2.2.1.3.10", Integer(6)),
        VarBind("1.3.6.1.2.1.2.2.1.4.1", Integer(65536)),
        VarBind("1.3.6.1.2.1.2.2.1.4.10", Integer(1500)),
        VarBind("1.3.6.1.2.1.2.2.1.5.1", Gauge(10000000)),
        VarBind("1.3.6.1.2.1.2.2.1.5.10", Gauge(4294967295)),
        VarBind("1.3.6.1.2.1.2.2.1.6.1", OctetString(b"")),
        VarBind(
            "1.3.6.1.2.1.2.2.1.6.10",
            OctetString(b"\x02\x42\xAC\x11\x00\x02"),
        ),
        VarBind("1.3.6.1.2.1.2.2.1.7.1", Integer(1)),
        VarBind("1.3.6.1.2.1.2.2.1.7.10", Integer(1)),
        VarBind("1.3.6.1.2.1.2.2.1.8.1", Integer(1)),
        VarBind("1.3.6.1.2.1.2.2.1.8.10", Integer(1)),
        VarBind("1.3.6.1.2.1.2.2.1.9.1", TimeTicks(0)),
        VarBind("1.3.6.1.2.1.2.2.1.9.10", TimeTicks(0)),
        VarBind("1.3.6.1.2.1.2.2.1.10.1", Counter(172)),
        VarBind("1.3.6.1.2.1.2.2.1.10.10", Counter(60558)),
        VarBind("1.3.6.1.2.1.2.2.1.11.1", Counter(2)),
        VarBind("1.3.6.1.2.1.2.2.1.11.10", Counter(564)),
        VarBind("1.3.6.1.2.1.2.2.1.12.1", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.12.10", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.13.1", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.13.10", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.14.1", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.14.10", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.15.1", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.15.10", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.16.1", Counter(172)),
        VarBind("1.3.6.1.2.1.2.2.1.16.10", Counter(44295)),
        VarBind("1.3.6.1.2.1.2.2.1.17.1", Counter(2)),
        VarBind("1.3.6.1.2.1.2.2.1.17.10", Counter(442)),
        VarBind("1.3.6.1.2.1.2.2.1.18.1", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.18.10", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.19.1", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.19.10", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.20.1", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.20.10", Counter(0)),
        VarBind("1.3.6.1.2.1.2.2.1.21.1", Gauge(0)),
        VarBind("1.3.6.1.2.1.2.2.1.21.10", Gauge(0)),
        VarBind("1.3.6.1.2.1.2.2.1.22.1", ObjectIdentifier(0, 0)),
        VarBind("1.3.6.1.2.1.2.2.1.22.10", ObjectIdentifier(0, 0)),
    ]
    assert result == expected


@pytest.mark.asyncio
async def test_bulktable(mocked_send):
    responses = readbytes_multiple("bulktable_response.hex")
    mocked_send.sender.set_values(responses)

    with patch("puresnmp.api.raw.get_request_id") as gri:
        request_ids = [
            1378164139,
            1378164140,
            1378164141,
            1378164142,
            1378164143,
        ]
        gri.side_effect = request_ids
        result = list(await mocked_send.bulktable("1.3.6.1.2.1.2.2"))

    expected = [
        {
            "0": "1",
            "1": Integer(1),
            "2": OctetString(b"lo"),
            "3": Integer(24),
            "4": Integer(65536),
            "5": Gauge(10000000),
            "6": OctetString(b""),
            "7": Integer(1),
            "8": Integer(1),
            "9": TimeTicks(0),
            "10": Counter(172),
            "11": Counter(2),
            "12": Counter(0),
            "13": Counter(0),
            "14": Counter(0),
            "15": Counter(0),
            "16": Counter(172),
            "17": Counter(2),
            "18": Counter(0),
            "19": Counter(0),
            "20": Counter(0),
            "21": Gauge(0),
            "22": ObjectIdentifier(0, 0),
        },
        {
            "0": "4",
            "1": Integer(4),
            "2": OctetString(b"eth0"),
            "3": Integer(6),
            "4": Integer(1500),
            "5": Gauge(4294967295),
            "6": OctetString(b"\x02B\xac\x11\x00\x02"),
            "7": Integer(1),
            "8": Integer(1),
            "9": TimeTicks(0),
            "10": Counter(548760),
            "11": Counter(3888),
            "12": Counter(0),
            "13": Counter(0),
            "14": Counter(0),
            "15": Counter(0),
            "16": Counter(186660),
            "17": Counter(1875),
            "18": Counter(0),
            "19": Counter(0),
            "20": Counter(0),
            "21": Gauge(0),
            "22": ObjectIdentifier(0, 0),
        },
    ]
    assert sorted(result, key=lambda x: x["0"]) == expected


class TestTraps(unittest.TestCase):
    def test_traps(self):
        raise pytest.skip("TODO")
        data_generator = readbytes_multiple("trap_requests.hex")

        def socket_response_generator():
            for blob in data_generator:
                yield SocketResponse(blob, SocketInfo("192.0.2.1", 64001))

        expected = [
            VarBind(
                ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 3, 0)), TimeTicks(794602)
            ),
            VarBind(
                ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)),
                ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1)),
            ),
            VarBind(
                ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1)),
                Integer(123456),
            ),
            VarBind(
                ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 3, 0)), TimeTicks(795345)
            ),
            VarBind(
                ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)),
                ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1)),
            ),
            VarBind(
                ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1)),
                Integer(123457),
            ),
            VarBind(
                ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 3, 0)), TimeTicks(795538)
            ),
            VarBind(
                ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)),
                ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1)),
            ),
            VarBind(
                ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1)),
                Integer(123459),
            ),
        ]
        result = []
        with patch("puresnmp.api.raw.Transport") as mck:
            mck().listen.return_value = socket_response_generator()
            for trap in traps():
                result.extend(trap.varbinds)
        self.assertEqual(result, expected)

    def test_traps_origin(self):
        """
        We want to see where a trap was sent from
        """
        raise pytest.skip("TODO")
        data_generator = readbytes_multiple("trap_requests.hex")

        def socket_response_generator():
            for blob in data_generator:
                yield SocketResponse(blob, SocketInfo("192.0.2.1", 64001))

        result = []
        with patch("puresnmp.api.raw.Transport") as mck:
            mck().listen.return_value = socket_response_generator()
            for trap in traps():
                result.append(trap.source)
        expected = [SocketInfo("192.0.2.1", 64001)] * 3
        self.assertEqual(result, expected)


@pytest.mark.asyncio
async def test_table_complex_row_id():
    client = RawClient("192.0.2.1", V2C("private"))
    values = [
        VarBind("1.2.1.1.1.1", OctetString(b"row 1.1.1 col 1")),
        VarBind("1.2.1.2.1.1", OctetString(b"row 2.1.1 col 1")),
        VarBind("1.2.2.1.1.1", OctetString(b"row 1.1.1 col 2")),
        VarBind("1.2.2.2.1.1", OctetString(b"row 2.1.1 col 2")),
    ]
    with patch(
        "puresnmp.api.raw.RawClient.walk", return_value=AsyncIter(values)
    ):
        result = await client.table("1.2", num_base_nodes=2)
    expected = [
        {
            "0": "1.1.1",
            "1": OctetString("row 1.1.1 col 1"),
            "2": OctetString("row 1.1.1 col 2"),
        },
        {
            "0": "2.1.1",
            "1": OctetString("row 2.1.1 col 1"),
            "2": OctetString("row 2.1.1 col 2"),
        },
    ]
    assert sorted(result, key=lambda x: x["0"]) == expected


@pytest.mark.asyncio
async def test_table():
    client = RawClient("192.0.2.1", V2C("private"))
    values = [
        VarBind("1.2.1.1.1", OctetString(b"row 1 col 1")),
        VarBind("1.2.1.1.2", OctetString(b"row 2 col 1")),
        VarBind("1.2.1.2.1", OctetString(b"row 1 col 2")),
        VarBind("1.2.1.2.2", OctetString(b"row 2 col 2")),
    ]
    with patch(
        "puresnmp.api.raw.RawClient.walk", return_value=AsyncIter(values)
    ):
        result = await client.table("1.2")
    expected = [
        {
            "0": "1",
            "1": OctetString("row 1 col 1"),
            "2": OctetString("row 1 col 2"),
        },
        {
            "0": "2",
            "1": OctetString("row 2 col 1"),
            "2": OctetString("row 2 col 2"),
        },
    ]
    assert sorted(result, key=lambda x: x["0"]) == expected


@pytest.mark.asyncio
async def test_table_base_oid():
    """
    The "table" function should be capable of detecting the
    "num_base_nodes" value by itself
    """
    client = RawClient("192.0.2.1", V2C("private"))
    values = [
        VarBind("1.2.1.1.1.1.1", OctetString(b"row 1.1.1 col 1")),
        VarBind("1.2.1.1.2.1.1", OctetString(b"row 2.1.1 col 1")),
        VarBind("1.2.1.2.1.1.1", OctetString(b"row 1.1.1 col 2")),
        VarBind("1.2.1.2.2.1.1", OctetString(b"row 2.1.1 col 2")),
    ]
    with patch(
        "puresnmp.api.raw.RawClient.walk", return_value=AsyncIter(values)
    ):
        result = await client.table("1.2")

    expected = [
        {
            "0": "1.1.1",
            "1": OctetString("row 1.1.1 col 1"),
            "2": OctetString("row 1.1.1 col 2"),
        },
        {
            "0": "2.1.1",
            "1": OctetString("row 2.1.1 col 1"),
            "2": OctetString("row 2.1.1 col 2"),
        },
    ]
    assert sorted(result, key=lambda x: x["0"]) == expected
