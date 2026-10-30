"""
This module implements the SNMPv3 "User Security Model" as defined in
:rfc:`3414`
"""

import time
from dataclasses import dataclass, replace
from textwrap import indent
from typing import Awaitable, Callable, Optional, Tuple, Union, cast

from x690 import decode
from x690.types import Integer, Null, ObjectIdentifier, OctetString, Sequence
from x690.util import INDENT_STRING, get_value_slice

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
from puresnmp.exc import NotInTimeWindow, SnmpError
from puresnmp.pdu import GetRequest, PDUContent, Report
from puresnmp.plugins.security import SecurityModel
from puresnmp.transport import MESSAGE_MAX_SIZE
from puresnmp.util import get_request_id, localise_key, validate_response_id
from puresnmp.varbind import VarBind

IDENTIFIER = 3

#: The usmStatsNotInTimeWindows counter (RFC 3414 section 5)
NOT_IN_TIME_WINDOWS = ObjectIdentifier("1.3.6.1.6.3.15.1.1.2.0")


def clock() -> float:
    """
    Return the local monotonic time in seconds.

    This is used to advance the local notion of a remote engine's time
    (see :rfc:`3414#section-2.3`).
    """
    return time.monotonic()


def find_time_window_report(message: Message) -> Optional[VarBind]:
    """
    Return the usmStatsNotInTimeWindows varbind if *message* is a decrypted
    Report carrying it, ``None`` otherwise.
    """
    if not isinstance(message.scoped_pdu, ScopedPDU):
        return None
    pdu = message.scoped_pdu.data
    if not isinstance(pdu, Report):
        return None
    for varbind in pdu.value.varbinds:
        if varbind.oid == NOT_IN_TIME_WINDOWS:
            return varbind
    return None


def reset_digest(
    message: Message, *, digest_length: int = auth.DEFAULT_DIGEST_LENGTH
) -> Message:
    """
    Replace the current message-digest in a message with zeroes.

    As the digest is embedded inside the message, it needs to be zeroed out
    when deriving the digest from a message. Otherwise the digest of the same
    message would change, because the digest changes.

    :param message: The message (with or without digest)
    :param digest_length: The digest length of the authentication method
        (12 for :rfc:`3414`, 16 to 48 for :rfc:`7860`)
    :returns: A new message with zeroed digest
    """
    # As per https://tools.ietf.org/html/rfc3414#section-6.3.1 and
    # https://tools.ietf.org/html/rfc7860#section-4.2, the authentication
    # parameters are initialised to as many zeroes as the digest is long
    secparams = USMSecurityParameters.decode(message.security_parameters)
    neutral = replace(secparams, auth_params=b"\x00" * digest_length)
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


class UnknownEngineId(USMError):
    """
    This error is raised when a message is processed that does not originate
    from the engine the request was sent to.
    """


class InsufficientSecurityLevel(USMError):
    """
    This error is raised when a message is processed that is protected with a
    lower security level than the one required by the credentials.
    """


def _child_slices(data: bytes, parent: slice, count: int) -> list[slice]:
    """
    Return the value slices of the first *count* TLVs inside *parent*.

    The lengths are taken from *data* as encoded (short or long form), so the
    slices point at the octets as they were received.

    :raises AuthenticationError: If a TLV does not fit inside *parent*
    """
    output = []
    index = parent.start
    for _ in range(count):
        if index >= parent.stop:
            raise AuthenticationError("Truncated SNMPv3 message")
        value, index = get_value_slice(data, index)
        if index > parent.stop:
            raise AuthenticationError("Malformed SNMPv3 message")
        output.append(value)
    return output


def locate_auth_params(whole_msg: bytes) -> slice:
    """
    Return the position of the msgAuthenticationParameters value inside an
    SNMPv3 message as received from the network.

    The message is not re-encoded, so the position is correct for any valid
    BER encoding (long-form lengths, non-minimal integers, ...).

    :param whole_msg: The complete SNMPv3 message as received
    :returns: The slice covering the octets of the authentication parameters
    :raises AuthenticationError: If the message structure is not as expected
    """
    message = get_value_slice(whole_msg, 0).bounds
    security_parameters = _child_slices(whole_msg, message, 3)[2]
    usm_params = _child_slices(whole_msg, security_parameters, 1)[0]
    auth_params = _child_slices(whole_msg, usm_params, 5)[4]
    return auth_params


def reset_received_digest(whole_msg: bytes, auth_params: bytes) -> bytes:
    """
    Replace the digest in a received SNMPv3 message with zeroes, in place.

    This is the received counterpart of :py:func:`reset_digest`: the digest
    must be computed over the bytes the remote engine sent (see
    :rfc:`3414#section-6.3.2`). Re-encoding a decoded message may produce
    different, equally valid, bytes and therefore a different digest.

    :param whole_msg: The complete SNMPv3 message as received
    :param auth_params: The decoded msgAuthenticationParameters, used to
        check that the correct octets are replaced
    :returns: The message with the authentication parameters zeroed
    :raises AuthenticationError: If the authentication parameters cannot be
        found in the message
    """
    position = locate_auth_params(whole_msg)
    if whole_msg[position] != auth_params:
        raise AuthenticationError(
            "Unable to locate the authentication parameters in the message"
        )
    zeroes = b"\x00" * len(auth_params)
    return whole_msg[: position.start] + zeroes + whole_msg[position.stop :]


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
        without_digest = reset_digest(
            unauthed_message, digest_length=auth.digest_length(auth_method)
        )
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
    message: Message,
    credentials: V3,
    security_params: USMSecurityParameters,
    whole_msg: Optional[bytes] = None,
) -> None:
    """
    Verify authenticity of the message using the credentials.

    The digest is computed over *whole_msg*, the message exactly as it was
    received (see :rfc:`3414#section-6.3.2`). Without it, the digest is
    computed over a re-encoded *message*, which only matches if the remote
    engine used the same encoding as puresnmp.

    :param message: The decoded message
    :param credentials: The user-credentials
    :param security_params: The decoded security parameters of *message*
    :param whole_msg: The complete message as received from the network
    :raises AuthenticationError: If the message is not authentic or its
        digest does not have the length of the authentication method
    """

    if not message.header.flags.auth:
        return

    if not credentials.auth:
        raise UnsupportedSecurityLevel(
            "Message requires authentication but auth-method is missing!"
        )

    auth_method = auth.create(credentials.auth.method)
    expected_length = auth.digest_length(auth_method)
    if len(security_params.auth_params) != expected_length:
        raise AuthenticationError(
            f"Unexpected digest length {len(security_params.auth_params)} "
            f"(expected {expected_length} for {credentials.auth.method!r})"
        )
    if whole_msg is None:
        without_digest = bytes(
            reset_digest(message, digest_length=expected_length)
        )
    else:
        without_digest = reset_received_digest(
            whole_msg, security_params.auth_params
        )
    is_authentic = auth_method.authenticate_incoming_message(
        credentials.auth.key,
        without_digest,
        security_params.auth_params,
        security_params.authoritative_engine_id,
    )
    if not is_authentic:
        raise AuthenticationError(
            "Incoming message could not be authenticated!"
        )


def check_security_level(
    message: Union[PlainMessage, EncryptedMessage], credentials: V3
) -> None:
    """
    Ensure that the message is protected at least as strongly as required by
    the credentials.

    Remote devices may legitimately send unauthenticated Report PDUs (f.ex.
    for an unknown user or a wrong digest). Those are surfaced as errors but
    their data is never returned.

    :raises InsufficientSecurityLevel: If the message is not sufficiently
        protected
    """
    flags = message.header.flags
    missing_auth = credentials.auth is not None and not flags.auth
    missing_priv = credentials.priv is not None and not flags.priv
    if not (missing_auth or missing_priv):
        return

    if isinstance(message.scoped_pdu, ScopedPDU) and isinstance(
        message.scoped_pdu.data, Report
    ):
        validate_usm_message(message)

    raise InsufficientSecurityLevel(
        f"Incoming message has an insufficient security level "
        f"(auth={flags.auth}, priv={flags.priv})"
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
        engine_config["local_timestamp"] = clock()

    def get_engine_timing(self, engine_id: bytes) -> Tuple[int, int]:
        """
        Return the local notion of the remote engine's boots and time.

        The engine time is advanced by the local time elapsed since the
        timing was learned (see :rfc:`3414#section-2.3`).

        :param engine_id: The ID of the authoritative engine
        :returns: A tuple of engine boots and engine time
        """
        engine_config = self.local_config[engine_id]
        engine_boots = engine_config["authoritative_engine_boots"]
        engine_time = engine_config["authoritative_engine_time"]
        timestamp = engine_config.get("local_timestamp")
        if timestamp is not None:
            engine_time += int(clock() - timestamp)
        return engine_boots, engine_time

    def update_engine_timing(
        self, engine_id: bytes, engine_boots: int, engine_time: int
    ) -> None:
        """
        Update the timing of a remote engine from an authenticated message.

        The values are only taken over if they are more recent than the
        local notion (see :rfc:`3414#section-3.2`, step 7b).

        :param engine_id: The ID of the authoritative engine
        :param engine_boots: The engine boots of the received message
        :param engine_time: The engine time of the received message
        """
        local_boots, local_time = self.get_engine_timing(engine_id)
        if engine_boots > local_boots or (
            engine_boots == local_boots and engine_time > local_time
        ):
            self.set_engine_timing(engine_id, engine_boots, engine_time)

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
        engine_boots, engine_time = self.get_engine_timing(security_engine_id)

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
        whole_msg: Optional[bytes] = None,
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

        # See https://tools.ietf.org/html/rfc3412#section-7.2
        engine_id = security_params.authoritative_engine_id
        if engine_id not in self.local_config:
            raise UnknownEngineId(f"Unexpected engine-id {engine_id!r}")

        verify_authentication(message, credentials, security_params, whole_msg)
        authenticated = message.header.flags.auth
        if authenticated:
            self.update_engine_timing(
                engine_id,
                security_params.authoritative_engine_boots,
                security_params.authoritative_engine_time,
            )
            self._check_time_window(message, security_params)
        check_security_level(message, credentials)
        message = decrypt_message(message, credentials)
        if authenticated:
            self._check_time_window(message, security_params)
        validate_usm_message(message)
        return message

    def _check_time_window(
        self, message: Message, security_params: USMSecurityParameters
    ) -> None:
        """
        Resynchronise with the remote engine if the authenticated *message*
        reports that our request was outside its time window.

        The remote engine reports its current timing in such a Report (see
        :rfc:`3414#section-4`), so it is taken over unconditionally.

        :raises NotInTimeWindow: If the message is such a Report
        """
        varbind = find_time_window_report(message)
        if varbind is None:
            return
        engine_id = security_params.authoritative_engine_id
        self.set_engine_timing(
            engine_id,
            security_params.authoritative_engine_boots,
            security_params.authoritative_engine_time,
        )
        raise NotInTimeWindow(
            str(varbind.oid), varbind.value.pythonize(), engine_id.hex()
        )

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
