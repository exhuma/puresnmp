import hmac
from dataclasses import replace

from puresnmp.adt import Message, USMSecurityParameters
from puresnmp.exc import SnmpError


def for_outgoing(hasher: callable, hmac_method: str) -> callable:
    def authenticate_outgoing_message(
        auth_key: bytes, message: Message
    ) -> Message:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """

        if message.security_parameters is None:
            # TODO: Better exception
            raise SnmpError(
                "Unable to authenticate messages without security params!"
            )

        digest = get_message_digest(hasher, hmac_method, auth_key, message)

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

    return authenticate_outgoing_message


def for_incoming(hasher: callable, hmac_method: str) -> callable:
    def authenticate_incoming_message(
        auth_key: bytes, message: Message
    ) -> None:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        if message.security_parameters is None:
            # TODO: Better exception
            raise SnmpError("authenticationFailure")

        received_digest = message.security_parameters.auth_params
        expected_digest = get_message_digest(
            hasher, hmac_method, auth_key, message
        )
        if received_digest != expected_digest:
            # TODO: Better exception
            raise SnmpError("authenticationFailure")

    return authenticate_incoming_message


def get_message_digest(
    hasher: callable, method: str, auth_key: bytes, message: Message
) -> bytes:
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

    auth_key = hasher(
        auth_key, message.security_parameters.authoritative_engine_id
    )

    data = bytes(message)
    mac = hmac.new(auth_key, data, digestmod=method)
    return mac.digest()[:12]
