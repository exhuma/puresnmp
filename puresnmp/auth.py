import hashlib
import hmac
from dataclasses import replace
from functools import lru_cache
from typing import Any, Callable, Dict, Type

from puresnmp.adt import Message, USMSecurityParameters
from puresnmp.exc import SnmpError


def password_to_key(
    hash_implementation: Callable[..., Any], padding_length: int
) -> Callable[[bytes, bytes], bytes]:
    @lru_cache(maxsize=None)
    def hasher(password: bytes, engine_id: bytes) -> bytes:
        hash_instance = hash_implementation()
        # Hash 1MB worth of data
        hash_size = 1024 * 1024
        num_words = hash_size // len(password)
        tmp = (password * (num_words + 1))[:hash_size]
        hash_instance.update(tmp)
        key = hash_instance.digest()
        localised_buffer = (
            key[:padding_length] + engine_id + key[:padding_length]
        )
        final_key = hash_implementation(localised_buffer).digest()
        return final_key

    hasher.__name__ = f"<hasher:{hash_implementation}>"  # type: ignore
    return hasher


class Auth:

    IDENTIFIER: str
    __registry: Dict[str, Type["Auth"]] = {}

    def __init_subclass__(cls: Type["Auth"]) -> None:
        if not hasattr(cls, "IDENTIFIER"):
            return
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

    def authenticate_incoming_message(
        self, auth_key: bytes, message: Message
    ) -> None:
        raise NotImplementedError("Not yet implemented")


class HashingAuth(Auth):
    IMPLEMENTATION: Callable[..., Any]
    HMAC_DIGESTMOD: str

    def _get_message_digest(self, auth_key: bytes, message: Message) -> bytes:
        if message.security_parameters is None:
            # TODO: Better exception
            raise SnmpError(
                "Unable to authenticate messages without security params!"
            )

        # As per https://tools.ietf.org/html/rfc3414#section-6.3.1,
        # the auth-key needs to be initialised to 12 zeroes
        message = replace(
            message,
            security_parameters=replace(
                message.security_parameters, auth_params=b"\x00" * 12
            ),
        )

        auth_key = self.IMPLEMENTATION(
            auth_key, message.security_parameters.authoritative_engine_id
        )

        data = bytes(message)
        mac = hmac.new(auth_key, data, digestmod=self.HMAC_DIGESTMOD)
        return mac.digest()[:12]

    def authenticate_outgoing_message(
        self, auth_key: bytes, message: Message
    ) -> Message:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """

        if message.security_parameters is None:
            # TODO: Better exception
            raise SnmpError(
                "Unable to authenticate messages without security params!"
            )

        digest = self._get_message_digest(auth_key, message)

        security_params = USMSecurityParameters(
            message.security_parameters.authoritative_engine_id,
            message.security_parameters.authoritative_engine_boots,
            message.security_parameters.authoritative_engine_time,
            message.security_parameters.user_name,
            digest,
            message.security_parameters.priv_params,
        )
        authed_message = Message(
            message.version,
            message.global_data,
            security_params,
            message.scoped_pdu,
        )
        return authed_message

    def authenticate_incoming_message(
        self, auth_key: bytes, message: Message
    ) -> None:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        if message.security_parameters is None:
            # TODO: Better exception
            raise SnmpError("authenticationFailure")

        received_digest = message.security_parameters.auth_params
        expected_digest = self._get_message_digest(auth_key, message)
        if received_digest != expected_digest:
            # TODO: Better exception
            raise SnmpError("authenticationFailure")


class MD5Auth(HashingAuth):
    IDENTIFIER = "usmHMACMD5AuthProtocol"
    IMPLEMENTATION = staticmethod(password_to_key(hashlib.md5, 16))
    HMAC_DIGESTMOD = "md5"


class SHAAuth(HashingAuth):
    IDENTIFIER = "usmHMACSHAAuthProtocol"
    IMPLEMENTATION = staticmethod(password_to_key(hashlib.sha1, 20))
    HMAC_DIGESTMOD = "sha1"
