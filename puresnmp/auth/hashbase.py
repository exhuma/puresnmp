"""
This module provides common code for hashing based authentication.
"""
import hmac
from typing import Callable

from typing_extensions import Protocol

from puresnmp.exc import SnmpError

THasher = Callable[[bytes, bytes], bytes]


class TOutgoing(Protocol):
    """
    Protocol for callables that authenticate outgoing SNMP messages
    """

    # pylint: disable=too-few-public-methods

    def __call__(self, auth_key: bytes, data: bytes, engine_id: bytes) -> bytes:
        # pylint: disable=unused-argument, missing-docstring
        ...


class TIncoming(Protocol):
    """
    Protocol for callables that authenticate incoming SNMP messages
    """

    # pylint: disable=too-few-public-methods

    def __call__(
        self,
        auth_key: bytes,
        data: bytes,
        received_digest: bytes,
        engine_id: bytes,
    ) -> None:
        # pylint: disable=unused-argument, missing-docstring
        ...


def for_outgoing(hasher: THasher, hmac_method: str) -> TOutgoing:
    """
    Create a new callable able to authenticate outgoing messages.

    :param hasher: A function used to apply a hashing algorithm.
    :param hmac_method: The specific HMAC implementation to use
    :return: A callable that can be used in a puresnmp authentication plugin
    """

    def authenticate_outgoing_message(
        auth_key: bytes, data: bytes, engine_id: bytes
    ) -> bytes:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        digest = get_message_digest(
            hasher,
            hmac_method,
            auth_key,
            data,
            engine_id,
        )
        return digest

    return authenticate_outgoing_message


def for_incoming(hasher: THasher, hmac_method: str) -> TIncoming:
    """
    Create a new callable able to authenticate incoming messages.

    :param hasher: A function used to apply a hashing algorithm.
    :param hmac_method: The specific HMAC implementation to use
    :return: A callable that can be used in a puresnmp authentication plugin
    """

    def authenticate_incoming_message(
        auth_key: bytes, data: bytes, received_digest: bytes, engine_id: bytes
    ) -> None:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        expected_digest = get_message_digest(
            hasher, hmac_method, auth_key, data, engine_id
        )
        if received_digest != expected_digest:
            # TODO: Better exception
            raise SnmpError("authenticationFailure")

    return authenticate_incoming_message


def get_message_digest(
    hasher: THasher,
    method: str,
    auth_key: bytes,
    encoded_message: bytes,
    engine_id: bytes,
) -> bytes:
    """
    Calculate the digest for a given message.

    :param hasher: A specific hash-implementation (f.ex.: ``hashlib.md5``)
    :param method: The digest-method to use
    :param auth_key: The authentication key for the user
    :param encoded_message: The SNMP message as bytes
    :param engine_id: The ID of the receiving engine
    """
    auth_key = hasher(auth_key, engine_id)
    mac = hmac.new(auth_key, encoded_message, digestmod=method)
    return mac.digest()[:12]
