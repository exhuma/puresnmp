import hashlib
from binascii import unhexlify

import puresnmp.auth as auth


def test_md5_key():
    engine_id = unhexlify("000000000000000000000002")
    hasher = auth.password_to_key(hashlib.md5, 16)
    result = hasher(b"maplesyrup", engine_id)
    expected = unhexlify("526f5eed9fcce26f8964c2930787d82b")
    assert result == expected


def test_sha_key():
    engine_id = unhexlify("000000000000000000000002")
    hasher = auth.password_to_key(hashlib.sha1, 20)
    result = hasher(b"maplesyrup", engine_id)
    expected = unhexlify("6695febc9288e36282235fc7151f128497b38f3f")
    assert result == expected
