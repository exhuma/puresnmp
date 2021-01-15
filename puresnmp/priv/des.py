import hashlib
from random import randint
from typing import Generator, Tuple

from Crypto.Cipher import DES as CDES

from puresnmp.exc import SnmpError
from puresnmp.util import password_to_key

IDENTIFIER = "des"


def pad_packet(data: bytes, block_size: int = 8) -> bytes:
    """
    Pads a packet to being a multiple of *block_size*.

    In x.690 BER encoding, the data contains length-information so
    "over-sized" data can be decoded without issue. This function simply adds
    zeroes at the end for as needed.

    Packets also don't need to be "unpadded" for the same reason
    See https://tools.ietf.org/html/rfc3414#section-8.1.1.3
    """
    rest = len(data) % block_size
    if rest == 0:
        return data
    numpad = block_size - rest
    return data + numpad * b"\x00"


def reference_saltpot() -> Generator[int, None, None]:
    salt = randint(1, 0xFFFFFFFF - 1)
    while True:
        yield salt
        salt += 1
        if salt == 0xFFFFFFFF:
            salt = 0


SALTPOT = reference_saltpot()


def encrypt_data(
    key: bytes, engine_id: bytes, engine_boots: int, data: bytes
) -> Tuple[bytes, bytes]:
    """
    See https://tools.ietf.org/html/rfc3414#section-1.6
    """

    hasher = password_to_key(hashlib.md5, 16)
    private_privacy_key = hasher(key, engine_id)
    des_key = private_privacy_key[:8]
    pre_iv = private_privacy_key[8:]

    local_salt = next(SALTPOT)
    salt = (engine_boots & 0xFF).to_bytes(4, "big") + (
        local_salt & 0xFF
    ).to_bytes(4, "big")
    init_vector = bytes(a ^ b for a, b in zip(salt, pre_iv))
    local_salt = next(SALTPOT)

    cdes = CDES.new(des_key, mode=CDES.MODE_CBC, IV=init_vector)
    padded = pad_packet(data)
    encrypted = cdes.encrypt(padded)
    return encrypted, salt


def decrypt_data(
    decrypt_key: bytes,
    data: bytes,
    authoritative_engine_id: bytes,
    salt: bytes,
) -> bytes:
    """
    See https://tools.ietf.org/html/rfc3414#section-1.6
    """
    if len(data) % 8 != 0:
        raise SnmpError(
            "Invalid payload lenght for decryption (not a multiple of 8)"
        )

    hasher = password_to_key(hashlib.md5, 16)
    private_privacy_key = hasher(decrypt_key, authoritative_engine_id)
    des_key = private_privacy_key[:8]

    pre_iv = private_privacy_key[8:]
    init_vector = bytes(a ^ b for a, b in zip(salt, pre_iv))
    cdes = CDES.new(des_key, mode=CDES.MODE_CBC, IV=init_vector)
    decrypted = cdes.decrypt(data)
    if data and not decrypted:
        raise SnmpError("Unable to decrypt data!")
    return decrypted
