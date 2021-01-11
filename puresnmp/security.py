from dataclasses import replace
from typing import Any, Dict, Type

from x690.types import Integer, OctetString, Sequence, pop_tlv

from puresnmp.adt import Message, USMSecurityParameters, V3Flags
from puresnmp.auth import Auth
from puresnmp.credentials import V3, Credentials
from puresnmp.exc import InvalidSecurityModel, NotInTimeWindow, SnmpError
from puresnmp.priv import Priv


class UnsupportedSecurityLevel(SnmpError):
    """
    Raised on errors related to security levels
    """


class UnknownSecurityModel(SnmpError):
    def __init__(self, identifier: int) -> None:
        super().__init__(f"No security model with ID {identifier} found!")


class SecurityModel:
    """
    Each Security Model defines the applied protecion on SNMP PDUs
    """

    IDENTIFIER: int

    #: The "Local Configuration Datastor" (LCD)
    local_config: Dict[bytes, Dict[str, Any]]

    #: A default local security config for unknown engine IDs
    default_auth: Dict[bytes, Dict[str, Any]]

    __registry: Dict[int, Type["SecurityModel"]] = {}

    def __init_subclass__(cls: Type["SecurityModel"]) -> None:
        SecurityModel.__registry[cls.IDENTIFIER] = cls

    def __init__(self) -> None:
        self.local_config = {}
        self.default_auth = {}

    def set_default_auth(self, auth: Dict[bytes, Dict[str, Any]]) -> None:
        self.default_auth = auth

    @staticmethod
    def create(identifier: int) -> "SecurityModel":
        """
        Creates a message processing model according to the given identifier.
        """
        if identifier not in SecurityModel.__registry:
            raise InvalidSecurityModel(identifier)
        return SecurityModel.__registry[identifier]()

    def generate_request_message(
        self,
        message: Message,
        security_engine_id: bytes,
        security_name: bytes,
        security_level: V3Flags,
    ) -> Message:
        raise NotImplementedError("Not yet implemented")

    def process_incoming_message(self, message: Message) -> Message:
        raise NotImplementedError("Not yet implemented")


class UserSecurityModel(SecurityModel):
    IDENTIFIER = 3

    def set_engine_timing(self, engine_id, boots, time):
        # TODO redundant with set_timing_values?
        engine_config = self.local_config.setdefault(engine_id, {})
        engine_config["authoritative_engine_boots"] = boots
        engine_config["authoritative_engine_time"] = time

    def set_default_auth(self, auth: Dict[bytes, Dict[str, Any]]) -> None:
        self.default_auth = auth

    def generate_request_message(
        self,
        message: Message,
        security_engine_id: bytes,
        credentials: Credentials,
    ) -> Message:
        if not isinstance(credentials, V3):
            raise TypeError(
                "Credentials must be a V3 instance for this scurity model!"
            )

        security_name = credentials.username.encode("ascii")
        engine_config = self.local_config[security_engine_id]
        engine_boots = engine_config["authoritative_engine_boots"]
        engine_time = engine_config["authoritative_engine_time"]

        message = replace(
            message,
            security_parameters=USMSecurityParameters(
                security_engine_id,
                engine_boots,
                engine_time,
                security_name,
                b"",
                b"",
            ),
        )

        if credentials.priv is not None and not all(
            [credentials.priv.method, credentials.auth.method]
        ):
            raise UnsupportedSecurityLevel(
                f"Security level needs privacy, but either auth-proto or "
                f"priv-proto are missing for user {security_name!r}"
            )

        if credentials.priv is not None:
            priv_method = Priv.create(credentials.priv.method)
            key = credentials.priv.key
            try:
                message = priv_method.encrypt_data(key, message)
            except Exception as exc:
                # TODO Use a proper app-exception here
                raise SnmpError("EncryptionError") from exc
        else:
            encoded_pdu = bytes(message.scoped_pdu)
            priv_params = b""

        if credentials.auth is not None and not credentials.auth.method:
            raise UnsupportedSecurityLevel(
                f"Security level needs authentication, but auth-proto "
                f"is missing for user {security_name!r}"
            )
        if credentials.auth is not None:
            auth_method = Auth.create(credentials.auth.method)
            try:
                auth_result = auth_method.authenticate_outgoing_message(
                    credentials.auth.key, message
                )
                return auth_result  # XXX return misplaced
            except Exception as exc:
                # TODO improve error message
                raise SnmpError("authenticationFailure") from exc
        else:
            auth_params = b""

        security_params = USMSecurityParameters(
            authoritative_engine_id=security_engine_id,
            authoritative_engine_boots=engine_boots,
            authoritative_engine_time=engine_time,
            user_name=security_name,
            auth_params=auth_params,
            priv_params=priv_params,
        )

        secured_message = Message(
            message.version,
            message.global_data,
            security_params,
            encoded_pdu,
        )
        return secured_message

    def process_incoming_message(
        self, message: Message, credentials: Credentials
    ) -> Message:
        # TODO: Validate engine-id.
        # TODO: Validate incoming username against the request

        security_engine_id = message.security_parameters.authoritative_engine_id
        security_name = message.security_parameters.user_name
        engine_config = self.local_config[security_engine_id]
        if security_name != credentials.username.encode("ascii"):
            # See https://tools.ietf.org/html/rfc3414#section-3.1
            # TODO better exception class
            raise SnmpError(f"Unknown User {security_name!r}")

        auth_method = Auth.create(credentials.auth.method)
        if message.global_data.flags.auth and not auth_method:
            raise UnsupportedSecurityLevel(
                f"Security level needs authentication, but auth-proto "
                f"is missing for user {security_name!r}"
            )
        if message.global_data.flags.auth:
            try:
                auth_method.authenticate_incoming_message(
                    credentials.auth.key, message
                )
            except Exception as exc:
                # TODO improve error message
                raise SnmpError("authenticationFailure") from exc

        if message.global_data.flags.priv:
            priv_method = Priv.create(credentials.priv.method)
            key = credentials.priv.key
            try:
                message = priv_method.decrypt_data(key, message)
            except Exception as exc:
                # TODO Use a proper app-exception here
                raise SnmpError("DecryptionError") from exc

        return message


class NullSecurityModel(SecurityModel):
    """
    This is a placeholder class for security models which don't implement any
    logic.

    A use-case is the "ANY" security model which is used during the discovery
    phase.
    """

    IDENTIFIER = 0


class SNMPv1SecurityModel(SecurityModel):
    IDENTIFIER = 1


class SNMPv2cSecurityModel(SecurityModel):
    IDENTIFIER = 2
