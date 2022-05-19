"""
Example plugin for :py:mod:`puresnmp`. This does no encryption, it's only an
example.
"""
from typing import NamedTuple

IDENTIFIER = "example"
IANA_ID = -1


class EncryptionResult(NamedTuple):
    ciphertext: bytes
    salt: bytes


def encrypt_data(
    localised_key: bytes,
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    data: bytes,
) -> EncryptionResult:
    """
    Encrypt the data
    """
    # This is where we would encrypt the data in "data"
    return EncryptionResult(data, b"")


def decrypt_data(
    localised_key: bytes,
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    salt: bytes,
    data: bytes,
) -> bytes:
    """
    See https://tools.ietf.org/html/rfc3826#section-3.1.4
    """
    # This is where we would decrypt the data
    return data
