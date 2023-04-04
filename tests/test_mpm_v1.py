import datetime
import typing

import pytest

import ipaddress
import x690.types

import puresnmp.credentials
import puresnmp.plugins.mpm
import puresnmp.v1_trap
import puresnmp.varbind


# Ignore the "Experimental SNMPv1 support" warning for now, until it can be removed.
@pytest.mark.filterwarnings("ignore::UserWarning")
def test_v1_trap_decode() -> None:
    async def handler(data: bytes) -> bytes:
        return b""

    raw_response = (
        b"\x30\x3b\x02\x01"  # SNMP
        b"\x00"  # version: version-1 (0)
        b"\x04\x06"
        b"\x70\x75\x62\x6c\x69\x63"  # community: public
        b"\xa4\x2e"  # data: trap (4)
        b"\x06\x09"  # trap
        b"\x2b\x06\x01\x04\x01\x81\xfd\x59\x01"  # enterprise: 1.3.6.1.4.1.32473.1 (iso.3.6.1.4.1.32473.1)
        b"\x40\x04"
        b"\xc0\xa8\x00\x01"  # agent-addr: 192.168.0.1
        b"\x02\x01"
        b"\x06"  # generic-trap: enterpriseSpecific (6)
        b"\x02\x01"
        b"\x7b"  # specific-trap: 123
        b"\x43\x02"
        b"\x01\xc8"  # time-stamp: 456
        b"\x30\x12"
        b"\x30\x10"  # variable-bindings: 1 item
        b"\x06\x0a"
        b"\x2b\x06\x01\x04\x01\x81\xfd\x59\x01\x00"  # Object Name: 1.3.6.1.4.1.32473.1.0 (iso.3.6.1.4.1.32473.1.0)
        b"\x02\x02"
        b"\x03\x15"  # Value (Integer32): 2
    )

    lcd: typing.Dict[str, typing.Any] = {}
    as_sequence = x690.types.Sequence.decode(raw_response)
    obj = typing.cast(
        typing.Tuple[
            x690.types.Integer, x690.types.OctetString, puresnmp.v1_trap.TrapV1
        ],
        as_sequence,
    )

    instance = puresnmp.plugins.mpm.create(obj[0].value, handler, lcd)
    result = instance.decode(raw_response, puresnmp.credentials.V1("public"))

    assert isinstance(result, puresnmp.v1_trap.TrapV1)
    t = typing.cast(puresnmp.v1_trap.TrapV1, result)
    tv = t.value
    assert tv.enterprise == x690.types.ObjectIdentifier("1.3.6.1.4.1.32473.1")
    assert tv.agent_addr == ipaddress.IPv4Address("192.168.0.1")
    assert tv.generic_trap is puresnmp.v1_trap.GenericTrap.ENTERPRISE_SPECIFIC
    assert tv.specific_trap == 123
    assert tv.time_stamp == datetime.timedelta(seconds=4.56)
    assert len(tv.varbinds) == 1
    vb = tv.varbinds[0]
    assert vb.oid == x690.types.ObjectIdentifier("1.3.6.1.4.1.32473.1.0")
    assert vb.value.value == 789
