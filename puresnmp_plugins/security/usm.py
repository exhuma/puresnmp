"""
This module implements the SNMPv3 "User Security Model" as defined in
:rfc:`3414`
"""
from dataclasses import dataclass, replace
from textwrap import indent
from typing import Awaitable, Callable, Union, cast

from x690 import decode
from x690.types import Integer, Null, ObjectIdentifier, OctetString, Sequence
from x690.util import INDENT_STRING

import puresnmp.plugins.auth as auth
import puresnmp.plugins.priv as priv
from puresnmp.adt import (
    EncryptedMessage,
    HeaderData,
    Message,
    PlainMessage,
    ScopedPDU,
    V3Flags,
)
from puresnmp.credentials import V3, Credentials
from puresnmp.exc import SnmpError
from puresnmp.pdu import GetRequest, PDUContent
from puresnmp.plugins.security import SecurityModel
from puresnmp.transport import MESSAGE_MAX_SIZE
from puresnmp.util import get_request_id, localise_key, validate_response_id

IDENTIFIER = 3


def reset_digest(message: Message) -> Message:
    """
    Replace the current message-digest in a message with zeroes.

    As the digest is embedded inside the message, it needs to be zeroed out
    when deriving the digest from a message. Otherwise the digest of the same
    message would change, because the digest changes.

    :param message: The message (with or without digest)
    :returns: A new message with zeroed digest
    """
    # As per https://tools.ietf.org/html/rfc3414#section-6.3.1,
    # the auth-key needs to be initialised to 12 zeroes
    secparams = USMSecurityParameters.decode(message.security_parameters)
    neutral = replace(secparams, auth_params=b"\x00" * 12)
    output = replace(
        message,
        security_parameters=bytes(neutral),
    )
    return output


class USMError(SnmpError):
    """
    Generic exception for errors cased by the USM module
    """


class UnsupportedSecurityLevel(USMError):
    """
    This error is raised when the data included in the credentials is invalid
    or incomplete.
    """


class EncryptionError(USMError):
    """
    This error is raised whenever something goes wrong during encryption
    """


class DecryptionError(USMError):
    """
    This error is raised whenever something goes wrong during decryption
    """


class AuthenticationError(USMError):
    """
    This error is raised whenever something goes wrong during authentication
    """


class UnknownUser(USMError):
    """
    This error is raised when a message is processed that is not consistent
    with the user-name passed in the credentials.
    """


@dataclass(frozen=True)
class DiscoData:
    """
    Helper class to wrap data received from a SNMPv3 discovery message.
    """

    #: The engine-id of the remote device
    authoritative_engine_id: bytes
    #: The number of boots of the remote device (encryption timeliness)
    authoritative_engine_boots: int
    #: The time-ticks since last boot of the remote device (encryption
    #: timeliness)
    authoritative_engine_time: int
    #: The number of requests received with an unknown client-engine-id
    unknown_engine_ids: int


@dataclass(frozen=True)
class USMSecurityParameters:
    """
    This class wraps the various values for the USM
    """

    authoritative_engine_id: bytes
    authoritative_engine_boots: int
    authoritative_engine_time: int
    user_name: bytes
    auth_params: bytes
    priv_params: bytes

    @staticmethod
    def decode(data: bytes) -> "USMSecurityParameters":
        """
        Construct a USMSecurityParameters instance from pure bytes
        """
        seq, _ = decode(data, enforce_type=Sequence)
        return USMSecurityParameters.from_snmp_type(seq)

    @staticmethod
    def from_snmp_type(seq: Sequence) -> "USMSecurityParameters":
        """
        Construct a USMSecurityParameters instance from an SNMP/X690 Sequence
        """
        return USMSecurityParameters(
            authoritative_engine_id=seq[0].pythonize(),
            authoritative_engine_boots=seq[1].pythonize(),
            authoritative_engine_time=seq[2].pythonize(),
            user_name=seq[3].pythonize(),
            auth_params=seq[4].pythonize(),
            priv_params=seq[5].pythonize(),
        )

    def __bytes__(self) -> bytes:
        return bytes(self.as_snmp_type())

    def as_snmp_type(self) -> Sequence:
        """
        Convert this instance into a plain SNMP (x690) object.
        """
        return Sequence(
            [
                OctetString(self.authoritative_engine_id),
                Integer(self.authoritative_engine_boots),
                Integer(self.authoritative_engine_time),
                OctetString(self.user_name),
                OctetString(self.auth_params),
                OctetString(self.priv_params),
            ]
        )

    def pretty(self, depth: int = 0) -> str:
        """
        Return a value for CLI display
        """
        idt = INDENT_STRING
        lines = ["Security Parameters"]
        lines.extend(
            [
                f"{idt}Engine ID   : {self.authoritative_engine_id!r}",
                f"{idt}Engine Boots: {self.authoritative_engine_boots}",
                f"{idt}Engine Time : {self.authoritative_engine_time}",
                f"{idt}Username    : {self.user_name!r}",
                f"{idt}Auth Params : {self.auth_params!r}",
                f"{idt}Priv Params : {self.priv_params!r}",
            ]
        )
        return indent("\n".join(lines), INDENT_STRING * depth)


def apply_encryption(
    message: PlainMessage,
    credentials: V3,
    security_name: bytes,
    security_engine_id: bytes,
    engine_boots: int,
    engine_time: int,
) -> Union[PlainMessage, EncryptedMessage]:
    """
    Derive a new encrypted message from a plain message given
    user-credentials and target-engine information.

    :param message: The unencrypted message
    :param credentials: The SNMPv3 credentials to be applied to the message
    :param security_name: The username used in the request
    :param security_engine_id: The engine-id of the remote device
    :param engine_boots: Encryption timeliness data as received from the
        discovery process
    :param engine_time: Encryption timeliness data as received from the
        discovery process
    :returns: Either an encrypted message, or a plain-message (depending on
        credential type)
    """

    # TODO: the security_name arg is redundant. Same value (different type)
    #       than credentials.username

    if credentials.priv is not None and not credentials.priv.method:
        raise UnsupportedSecurityLevel("Encryption method is missing")

    if credentials.priv is None:
        return replace(
            message,
            security_parameters=bytes(
                USMSecurityParameters(
                    security_engine_id,
                    engine_boots,
                    engine_time,
                    security_name,
                    b"",
                    b"",
                )
            ),
        )

    priv_method = priv.create(credentials.priv.method)
    localised_key = localise_key(credentials, security_engine_id)
    try:
        encrypted, salt = priv_method.encrypt_data(
            localised_key,
            security_engine_id,
            engine_boots,
            engine_time,
            bytes(message.scoped_pdu),
        )
        scoped_pdu = OctetString(encrypted)
    except Exception as exc:
        raise EncryptionError(f"Unable to encrypt message ({exc})") from exc

    unauthed_message = replace(
        message,
        scoped_pdu=scoped_pdu,
        security_parameters=bytes(
            USMSecurityParameters(
                security_engine_id,
                engine_boots,
                engine_time,
                security_name,
                b"",
                salt,
            )
        ),
    )
    return unauthed_message


def apply_authentication(
    unauthed_message: Union[PlainMessage, EncryptedMessage],
    credentials: V3,
    security_engine_id: bytes,
) -> Union[PlainMessage, EncryptedMessage]:
    """
    Add authentication-information to an SNMPv3 message

    :param unauthed_message: Either an encrypted or plain message that we
        want to update with authentication information.
    :param credentials: The user-credentials
    :param security_engine_id: The engine-id of the remote device
    :return: A message (of the same type) with authentication information
        added to and security_parameters of the message.
    """
    if credentials.auth is not None and not credentials.auth.method:
        raise UnsupportedSecurityLevel(
            "Incomplete data for authentication. "
            "Need both an auth-key and an auth-method!"
        )

    if credentials.auth is None:
        return unauthed_message

    auth_method = auth.create(credentials.auth.method)
    try:
        without_digest = reset_digest(unauthed_message)
        auth_result = auth_method.authenticate_outgoing_message(
            credentials.auth.key,
            bytes(without_digest),
            security_engine_id,
        )
        security_params = replace(
            USMSecurityParameters.decode(unauthed_message.security_parameters),
            auth_params=auth_result,
        )
        authed_message = replace(
            unauthed_message, security_parameters=bytes(security_params)
        )
        return authed_message
    except Exception as exc:
        raise AuthenticationError(
            f"Unable to authenticat the message ({exc})"
        ) from exc


def verify_authentication(
    message: Message, credentials: V3, security_params: USMSecurityParameters
) -> None:
    """
    Verify authenticity of the message using the credentials.

    :raises AuthenticationError: If the message is not authentic
    """

    if not message.header.flags.auth:
        return

    if not credentials.auth:
        raise UnsupportedSecurityLevel(
            "Message requires authentication but auth-method is missing!"
        )

    auth_method = auth.create(credentials.auth.method)
    without_digest = reset_digest(message)
    is_authentic = auth_method.authenticate_incoming_message(
        credentials.auth.key,
        bytes(without_digest),
        security_params.auth_params,
        security_params.authoritative_engine_id,
    )
    if not is_authentic:
        raise AuthenticationError(
            "Incoming message could not be authenticated!"
        )


def decrypt_message(
    message: Union[PlainMessage, EncryptedMessage], credentials: V3
) -> PlainMessage:
    """
    Decrypt a message using the given credentials
    """
    if isinstance(message, PlainMessage):
        return message

    if not credentials.priv:
        raise SnmpError("Attempting to decrypt a message without priv object")
    priv_method = priv.create(credentials.priv.method)
    key = credentials.priv.key
    if not isinstance(message.scoped_pdu, OctetString):
        raise SnmpError(
            "Unexpectedly received unencrypted PDU with a security level "
            "requesting encryption!"
        )
    security_parameters = USMSecurityParameters.decode(
        message.security_parameters
    )
    localised_key = localise_key(
        credentials, security_parameters.authoritative_engine_id
    )
    try:
        decrypted = priv_method.decrypt_data(
            localised_key,
            security_parameters.authoritative_engine_id,
            security_parameters.authoritative_engine_boots,
            security_parameters.authoritative_engine_time,
            security_parameters.priv_params,
            message.scoped_pdu.value,
        )
        message = cast(
            PlainMessage,
            replace(message, scoped_pdu=ScopedPDU.decode(decrypted)),
        )
    except Exception as exc:
        raise DecryptionError(f"Unable to decrypt message ({exc})") from exc
    return message


class UserSecurityModel(
    SecurityModel[PlainMessage, Union[PlainMessage, EncryptedMessage]]
):
    """
    Implementation of the use-security model as defined by
    :py:class:`puresnmp.security.SecurityModel`
    """

    def set_engine_timing(
        self,
        engine_id: bytes,
        engine_boots: int,
        engine_time: int,
    ) -> None:
        engine_config = self.local_config.setdefault(engine_id, {})
        engine_config["authoritative_engine_boots"] = engine_boots
        engine_config["authoritative_engine_time"] = engine_time

    def generate_request_message(
        self,
        message: PlainMessage,
        security_engine_id: bytes,
        credentials: Credentials,
    ) -> Union[PlainMessage, EncryptedMessage]:
        if not isinstance(credentials, V3):
            raise TypeError(
                "Credentials must be a V3 instance for this scurity model!"
            )

        security_name = credentials.username.encode("ascii")
        engine_config = self.local_config[security_engine_id]
        engine_boots = engine_config["authoritative_engine_boots"]
        engine_time = engine_config["authoritative_engine_time"]

        encrypted_message = apply_encryption(
            message,
            credentials,
            security_name,
            security_engine_id,
            engine_boots,
            engine_time,
        )

        authed_message = apply_authentication(
            encrypted_message, credentials, security_engine_id
        )

        return authed_message

    def process_incoming_message(
        self,
        message: Union[PlainMessage, EncryptedMessage],
        credentials: Credentials,
    ) -> PlainMessage:

        if not isinstance(credentials, V3):
            raise SnmpError("Supplied credentials is not a V3 instance!")

        security_params = USMSecurityParameters.decode(
            message.security_parameters
        )

        security_name = security_params.user_name
        if security_name != credentials.username.encode("ascii"):
            # See https://tools.ietf.org/html/rfc3414#section-3.1
            raise UnknownUser(f"Unknown user {security_name!r}")

        verify_authentication(message, credentials, security_params)
        message = decrypt_message(message, credentials)
        validate_usm_message(message)
        return message

    async def send_discovery_message(
        self,
        transport_handler: Callable[[bytes], Awaitable[bytes]],
    ) -> DiscoData:
        # Via https://tools.ietf.org/html/rfc3414#section-4
        #
        # The User-based Security Model requires that a discovery process
        # obtains sufficient information about other SNMP engines in order to
        # communicate with them. Discovery requires an non-authoritative SNMP
        # engine to learn the authoritative SNMP engine's snmpEngineID value
        # before communication may proceed. This may be accomplished by
        # generating a Request message with a securityLevel of noAuthNoPriv, a
        # msgUserName of zero-length, a msgAuthoritativeEngineID value of zero
        # length, and the varBindList left empty. The response to this message
        # will be a Report message containing the snmpEngineID of the
        # authoritative SNMP engine as the value of the
        # msgAuthoritativeEngineID field within the msgSecurityParameters
        # field. It contains a Report PDU with the usmStatsUnknownEngineIDs
        # counter in the varBindList.

        request_id = get_request_id()
        security_params = USMSecurityParameters(
            authoritative_engine_id=b"",
            authoritative_engine_boots=0,
            authoritative_engine_time=0,
            user_name=b"",
            auth_params=b"",
            priv_params=b"",
        )
        discovery_message = Message(
            Integer(3),
            HeaderData(
                request_id,
                MESSAGE_MAX_SIZE,
                V3Flags(False, False, True),
                3,
            ),
            bytes(security_params),
            ScopedPDU(
                OctetString(),
                OctetString(),
                GetRequest(PDUContent(request_id, [])),
            ),
        )
        payload = bytes(discovery_message)
        raw_response = await transport_handler(payload)
        response, _ = decode(raw_response, enforce_type=Sequence)
        if isinstance(response, Null):
            raise SnmpError("Unexpectedly got a NULL object")

        # Arguably, this should pass through the message-processing model
        # allowing for more complex implementations. However this would require
        # a back-reference to the MPM (calling something "above" the current
        # abstraction level). As there is currently no implementation known to
        # me that requires this, I opted to go for a simpler architecture
        # instead. This means that discovery-messages cannot be encrypted.
        # Which they currently are not. So this should do.
        response_msg = PlainMessage.from_sequence(response)

        response_id = response_msg.header.message_id
        validate_response_id(request_id, response_id)

        # The engine-id is available in two places: The response directly, and
        # also the Report PDU. In initial tests these values were identical,
        # and fetching them from the wrapping message would be easier. But
        # because the RFC explicitly states that it's the value from inside the
        # PDU I picked it out from there instead.
        security = USMSecurityParameters.decode(
            response_msg.security_parameters
        )
        wrapped_vars = response_msg.scoped_pdu.data.value.varbinds
        if not wrapped_vars:
            raise SnmpError("Invalid discovery response (no varbinds returned)")
        unknown_engine_id_var = wrapped_vars[0]
        if not unknown_engine_id_var.value:
            raise SnmpError("Discovery data did not contain valid data")
        unknown_engine_ids = unknown_engine_id_var.value.pythonize()

        out = DiscoData(
            authoritative_engine_id=security.authoritative_engine_id,
            authoritative_engine_boots=security.authoritative_engine_boots,
            authoritative_engine_time=security.authoritative_engine_time,
            unknown_engine_ids=unknown_engine_ids,
        )
        return out


def validate_usm_message(message: PlainMessage) -> None:
    """
    If the message contains known error-indicators, raise an appropriate
    exception.

    :raises SnmpError: If an error was found
    """
    pdu = message.scoped_pdu.data.value
    errors = {
        ObjectIdentifier(
            "1.3.6.1.6.3.15.1.1.1.0"
        ): "Unsupported security level",
        ObjectIdentifier("1.3.6.1.6.3.15.1.1.2.0"): "Not in time window",
        ObjectIdentifier("1.3.6.1.6.3.15.1.1.3.0"): "Unknown user-name",
        ObjectIdentifier("1.3.6.1.6.3.15.1.1.4.0"): "Unknown engine-id",
        ObjectIdentifier("1.3.6.1.6.3.15.1.1.5.0"): "Wrong message digest",
        ObjectIdentifier("1.3.6.1.6.3.15.1.1.6.0"): "Unable to decrypt",
    }
    for varbind in pdu.varbinds:
        if varbind.oid in errors:
            msg = errors[varbind.oid]
            raise SnmpError(f"Error response from remote device: {msg}")


def create() -> UserSecurityModel:
    """
    Creates a new instance of the USM
    """
    return UserSecurityModel()
