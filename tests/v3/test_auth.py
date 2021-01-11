import puresnmp.auth as auth


def test_password_to_key():
    from hashlib import md5

    hasher = auth.password_to_key(md5, 16)
    result = hasher(b"foo", b"bar")
    expected = b"x\xf4\xdf-#\x19\x95\xe0\x8f\xcd\x1f{\xa87\x99\x06"
    assert result == expected