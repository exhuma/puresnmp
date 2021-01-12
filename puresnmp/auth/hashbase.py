import hmac

from puresnmp.exc import SnmpError
from typing import Callable
from typing_extensions import Protocol

THasher = Callable[[bytes, bytes], bytes]


class TOutgoing(Protocol):
    def __call__(self, auth_key: bytes, data: bytes, engine_id: bytes) -> bytes:
        # pylint: disable=unused-argument
        ...


class TIncoming(Protocol):
    def __call__(
        self,
        auth_key: bytes,
        data: bytes,
        received_digest: bytes,
        engine_id: bytes,
    ) -> None:
        ...


def for_outgoing(hasher: THasher, hmac_method: str) -> TOutgoing:
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
    auth_key = hasher(auth_key, engine_id)
    mac = hmac.new(auth_key, encoded_message, digestmod=method)
    return mac.digest()[:12]
