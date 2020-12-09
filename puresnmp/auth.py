import hashlib
import hmac
import itertools
from typing import Any, Callable, Dict, Type

from puresnmp.adt import Message, USMSecurityParameters
from puresnmp.exc import SnmpError


def password_to_key(
    hash_implementation: Callable[..., Any], padding_length: int
) -> Callable[[bytes, bytes], bytes]:
    def hasher(password: bytes, engine_id: bytes) -> bytes:
        hash_instance = hash_implementation()
        chars = itertools.cycle(password)
        count = 0
        # Hash 1MB worth of data
        while count < (1024 * 1024):
            buffer = bytes(next(chars) for char in range(64))
            hash_instance.update(buffer)
            count += 64
        key = hash_instance.digest()
        localised_buffer = (
            key[:padding_length] + engine_id + key[:padding_length]
        )
        final_key = hash_implementation(localised_buffer).digest()
        return final_key

    return hasher


password_to_key_md5 = password_to_key(hashlib.md5, 16)
password_to_key_sha1 = password_to_key(hashlib.sha1, 20)


class Auth:

    IDENTIFIER: str
    __registry: Dict[str, Type["Auth"]] = {}

    def __init_subclass__(cls: Type["Auth"]) -> None:
        Auth.__registry[cls.IDENTIFIER] = cls

    @staticmethod
    def create(identifier: str) -> "Auth":
        """
        Creates a message processing model according to the given identifier.
        """
        if identifier not in Auth.__registry:
            # TODO more precise exception
            raise SnmpError(f"Unknown auth-protocol: {identifier!r}")
        return Auth.__registry[identifier]()

    def authenticate_outgoing_message(
        self, auth_key: bytes, message: Message
    ) -> Message:
        raise NotImplementedError("Not yet implemented")


class MD5Auth(Auth):
    IDENTIFIER = "usmHMACMD5AuthProtocol"

    def authenticate_outgoing_message(
        self, auth_key: bytes, message: Message
    ) -> Message:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """

        if message.security_parameters is None:
            raise SnmpError(
                "Unable to authenticate messages without security params!"
            )

        # As per https://tools.ietf.org/html/rfc3414#section-6.3.1,
        # the auth-key needs to be initialised to 12 zeroes
        message.security_parameters.auth_params = b"\x00" * 12

        auth_key = password_to_key_md5(
            auth_key, message.security_parameters.authoritative_engine_id
        )

        data = bytes(message)
        mac = hmac.new(auth_key, data, digestmod="md5")
        output = mac.digest()[:12]
        security_params = USMSecurityParameters(
            message.security_parameters.authoritative_engine_id,
            message.security_parameters.authoritative_engine_boots,
            message.security_parameters.authoritative_engine_time,
            message.security_parameters.user_name,
            output,
            message.security_parameters.priv_params,
        )
        authed_message = Message(
            message.version,
            message.global_data,
            security_params,
            message.scoped_pdu,
        )
        return authed_message
