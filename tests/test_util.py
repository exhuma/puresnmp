"""
Unit-tests for utility functions
"""
import hashlib
from binascii import unhexlify
from ipaddress import ip_address

from x690.types import Null, ObjectIdentifier

import puresnmp.util as util
from puresnmp.pdu import VarBind
from puresnmp.util import (
    WalkRow,
    get_unfinished_walk_oids,
    group_varbinds,
    password_to_key,
)

OID = ObjectIdentifier


def test_group_varbinds():
    """
    "group_varbinds" should convert an interleaved list of OIDs into a more
    usable dictionary.
    """
    varbinds = [
        VarBind(OID("1.1.1"), Null()),
        VarBind(OID("2.2.1"), Null()),
        VarBind(OID("3.3.1"), Null()),
        VarBind(OID("1.1.2"), Null()),
        VarBind(OID("2.2.2"), Null()),
        VarBind(OID("3.3.2"), Null()),
        VarBind(OID("1.1.3"), Null()),
        VarBind(OID("2.2.3"), Null()),
        VarBind(OID("3.3.3"), Null()),
    ]
    effective_roots = [
        OID("1.1"),
        OID("2.2"),
        OID("3.3"),
    ]
    result = group_varbinds(varbinds, effective_roots)
    expected = {
        OID("1.1"): [
            VarBind(OID("1.1.1"), Null()),
            VarBind(OID("1.1.2"), Null()),
            VarBind(OID("1.1.3"), Null()),
        ],
        OID("2.2"): [
            VarBind(OID("2.2.1"), Null()),
            VarBind(OID("2.2.2"), Null()),
            VarBind(OID("2.2.3"), Null()),
        ],
        OID("3.3"): [
            VarBind(OID("3.3.1"), Null()),
            VarBind(OID("3.3.2"), Null()),
            VarBind(OID("3.3.3"), Null()),
        ],
    }

    assert result == expected


def test_get_unfinished_walk_oids():
    """
    Using get_unfinished_walk_oids should tell us which OIDs are not yet
    completed in the existing OID groups (by looking at the OIDs)
    """
    oid_groups = {
        OID("1.1"): [
            VarBind(OID("1.1.1"), Null()),
            VarBind(OID("1.1.2"), Null()),
        ],
        OID("2.2"): [
            VarBind(OID("2.2.1"), Null()),
            VarBind(OID("2.2.2"), Null()),
        ],
        OID("3.3"): [
            VarBind(OID("3.3.1"), Null()),
            VarBind(OID("3.4.2"), Null()),
        ],
    }
    result = get_unfinished_walk_oids(oid_groups)
    expected = [
        (OID("1.1"), WalkRow(VarBind(OID("1.1.2"), Null()), unfinished=True)),
        (OID("2.2"), WalkRow(VarBind(OID("2.2.2"), Null()), unfinished=True)),
    ]
    assert result == expected


def test_password_to_key():
    hasher = password_to_key(hashlib.md5, 16)
    result = hasher(b"foo", b"bar")
    expected = b"x\xf4\xdf-#\x19\x95\xe0\x8f\xcd\x1f{\xa87\x99\x06"
    assert result == expected


def test_md5_key():
    """
    Ensure we conform to https://tools.ietf.org/html/rfc3414#appendix-A.3.1
    """
    engine_id = unhexlify("000000000000000000000002")
    hasher = password_to_key(hashlib.md5, 16)
    result = hasher(b"maplesyrup", engine_id)
    expected = unhexlify("526f5eed9fcce26f8964c2930787d82b")
    assert result == expected


def test_sha_key():
    """
    Ensure we conform to https://tools.ietf.org/html/rfc3414#appendix-A.3.2
    """
    engine_id = unhexlify("000000000000000000000002")
    hasher = password_to_key(hashlib.sha1, 20)
    result = hasher(b"maplesyrup", engine_id)
    expected = unhexlify("6695febc9288e36282235fc7151f128497b38f3f")
    assert result == expected


def test_generate_engine_id_ip():
    ip = ip_address("192.0.2.1")
    result = util.generate_engine_id_ip(696, ip)
    expected = b"\x80\x00\x02\xb8\x01" + ip.packed
    assert result == expected


def test_generate_engine_id_mac():
    result = util.generate_engine_id_mac(696, "00:01:02:03:04:05:06:07")
    expected = b"\x80\x00\x02\xb8\x03" + b"\x00\x01\x02\x03\x04\x05\x06\x07"
    assert result == expected


def test_generate_engine_id_text():
    result = util.generate_engine_id_text(696, "hello")
    expected = b"\x80\x00\x02\xb8\x04" + b"hello"
    assert result == expected


def test_generate_engine_id_octets():
    result = util.generate_engine_id_octets(696, b"hello")
    expected = b"\x80\x00\x02\xb8\x05" + b"hello"
    assert result == expected
