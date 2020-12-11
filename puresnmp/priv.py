import hashlib
from dataclasses import replace
from random import randint
from typing import Dict, Generator, Optional, Type

import pyDes

# TODO: remove dependency on OctetString
from x690.types import OctetString

from puresnmp.adt import Message, ScopedPDU
from puresnmp.auth import password_to_key
from puresnmp.exc import SnmpError


def reference_saltpot() -> int:
    salt = randint(1, 0xFFFFFFFF - 1)
    while True:
        yield salt
        salt += 1
        if salt == 0xFFFFFFFF:
            salt = 0


class Priv:

    IDENTIFIER: str
    __registry: Dict[str, Type["Priv"]] = {}

    def __init_subclass__(cls: Type["Priv"]) -> None:
        if not hasattr(cls, "IDENTIFIER"):
            return
        Priv.__registry[cls.IDENTIFIER] = cls

    @staticmethod
    def create(identifier: str) -> "Priv":
        """
        Creates a message processing model according to the given identifier.
        """
        if identifier not in Priv.__registry:
            # TODO more precise exception
            raise SnmpError(f"Unknown auth-protocol: {identifier!r}")
        return Priv.__registry[identifier]()

    def encrypt_data(self, key: bytes, message: Message) -> Message:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        raise NotImplementedError("Not yet implemented")

    def decrypt_data(
        self, decrypt_key: bytes, priv_params: bytes, message: Message
    ) -> Message:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        raise NotImplementedError("Not yet implemented")


class DES(Priv):
    IDENTIFIER = "usmDESPrivProtocol"

    def __init__(
        self, saltpot: Optional[Generator[int, None, None]] = None
    ) -> None:
        if saltpot is None:
            self.saltpot = reference_saltpot()

    def encrypt_data(self, key: bytes, message: Message) -> Message:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """

        if message.security_parameters is None:
            raise SnmpError(
                "Unable to encrypt a message without security params!"
            )

        hasher = password_to_key(hashlib.md5, 16)
        private_privacy_key = hasher(
            key, message.security_parameters.authoritative_engine_id
        )
        des_key = private_privacy_key[:8]
        pre_iv = private_privacy_key[8:]

        local_salt = next(self.saltpot)
        engine_boots = message.security_parameters.authoritative_engine_boots
        salt = (engine_boots & 0xFF).to_bytes(4, "big") + (
            local_salt & 0xFF
        ).to_bytes(4, "big")
        init_vector = bytes(a ^ b for a, b in zip(salt, pre_iv))
        message = replace(
            message,
            security_parameters=replace(
                message.security_parameters, priv_params=salt
            ),
        )
        local_salt = next(self.saltpot)

        des = pyDes.des(
            des_key, mode=pyDes.CBC, IV=init_vector, padmode=pyDes.PAD_PKCS5
        )
        encrypted = des.encrypt(bytes(message.scoped_pdu))
        message = replace(message, scoped_pdu=OctetString(encrypted))
        return message

    def decrypt_data(self, decrypt_key: bytes, message: Message) -> Message:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        if not isinstance(message.scoped_pdu, OctetString):
            raise SnmpError(
                "Unexpectedly received unencrypted PDU with a security level requesting encryption!"
            )
        if len(message.scoped_pdu.value) % 8 != 0:
            raise SnmpError(
                "Invalid payload lenght for decryption (not a multiple of 8)"
            )
        if message.security_parameters is None:
            raise SnmpError(
                "Unable to decrypt a message without security parameters!"
            )

        hasher = password_to_key(hashlib.md5, 16)
        private_privacy_key = hasher(
            decrypt_key, message.security_parameters.authoritative_engine_id
        )
        des_key = private_privacy_key[:8]
        pre_iv = private_privacy_key[8:]
        salt = message.security_parameters.priv_params
        init_vector = bytes(a ^ b for a, b in zip(salt, pre_iv))
        des = pyDes.des(
            des_key, mode=pyDes.CBC, IV=init_vector, padmode=pyDes.PAD_PKCS5
        )
        decrypted = des.decrypt(message.scoped_pdu.value)
        message = replace(message, scoped_pdu=ScopedPDU.decode(decrypted))
        return message
