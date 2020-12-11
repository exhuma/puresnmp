from typing import Any, Dict, Type
from dataclasses import replace

from x690.types import Integer, OctetString, Sequence, pop_tlv

from puresnmp.adt import Message, USMSecurityParameters, V3Flags
from puresnmp.auth import Auth
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
        security_name: bytes,
        security_level: V3Flags,
    ) -> Message:
        engine_config = self.local_config[security_engine_id]
        if "users" not in engine_config:
            engine_config["users"] = self.default_auth or {}
        if security_name not in engine_config["users"]:
            # See https://tools.ietf.org/html/rfc3414#section-3.1
            # TODO better exception class
            raise SnmpError(f"Unknown User {security_name!r}")

        user_config = engine_config["users"][security_name]
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

        if security_level.priv and not all(
            [user_config["priv_proto"], user_config["auth_proto"]]
        ):
            raise UnsupportedSecurityLevel(
                f"Security level needs privacy, but either auth-proto or "
                f"priv-proto are missing for user {security_name!r}"
            )

        if security_level.priv:
            priv_proto = Priv.create(user_config.get("priv_proto"))
            key = user_config["priv_key"]
            try:
                message = priv_proto.encrypt_data(key, message)
            except Exception as exc:
                # TODO Use a proper app-exception here
                raise SnmpError("EncryptionError") from exc
        else:
            encoded_pdu = bytes(message.scoped_pdu)
            priv_params = b""

        if security_level.auth and not user_config["auth_proto"]:
            raise UnsupportedSecurityLevel(
                f"Security level needs authentication, but auth-proto "
                f"is missing for user {security_name!r}"
            )
        if security_level.auth:
            auth_proto = Auth.create(user_config.get("auth_proto"))
            try:
                auth_result = auth_proto.authenticate_outgoing_message(
                    user_config["auth_key"], message
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

    def process_incoming_message(self, message: Message) -> Message:
        # TODO: Validate engine-id.
        # TODO: Validate incoming username against the request

        security_engine_id = message.security_parameters.authoritative_engine_id
        security_name = message.security_parameters.user_name
        engine_config = self.local_config[security_engine_id]
        if security_name not in engine_config["users"]:
            # See https://tools.ietf.org/html/rfc3414#section-3.1
            # TODO better exception class
            raise SnmpError(f"Unknown User {security_name!r}")
        user_config = engine_config["users"][security_name]

        auth_proto = Auth.create(user_config.get("auth_proto"))
        if message.global_data.flags.auth and not auth_proto:
            raise UnsupportedSecurityLevel(
                f"Security level needs authentication, but auth-proto "
                f"is missing for user {security_name!r}"
            )
        if message.global_data.flags.auth:
            try:
                auth_proto.authenticate_incoming_message(
                    user_config["auth_key"], message
                )
            except Exception as exc:
                # TODO improve error message
                raise SnmpError("authenticationFailure") from exc

        if message.global_data.flags.priv:
            priv_proto = Priv.create(user_config.get("priv_proto"))
            key = user_config["priv_key"]
            try:
                message = priv_proto.decrypt_data(key, message)
            except Exception as exc:
                # TODO Use a proper app-exception here
                raise SnmpError("DecryptionError") from exc

        return message

        # XXX ----------------------------

        message_data, _ = pop_tlv(data)
        secparms = USMSecurityParameters.decode(message_data[2].pythonize())

        # See https://tools.ietf.org/html/rfc3414#section-3.2

        from pprint import pformat

        auth_key = localized_auth_key(
            user_auth_key, section.auth_engine_id, user_auth_algo
        )

        if security_level.auth:
            self.authenticate_incoming_message(
                auth_key, secparms.auth_params, data
            )

        1 / 0

        engine_boots = 2147483647  # XXX TODO
        local_engine_time = 0  # XXX TODO
        msg.engine_time = 0  # XXX TODO
        local_engine_boots = 0  # XXX TODO
        msg.engine_boots = 0  # XXX TODO
        oid_usmStatsNotInTimeWindows = "1.2.3"
        usmStatsNotInTimeWindows_value = 1
        if (
            engine_boots == 2147483647
            or local_engine_boots != msg.engine_boots
            or abs(local_engine_time - msg.engine_time) > 150
        ):
            raise NotInTimeWindow(
                oid_usmStatsNotInTimeWindows,
                usmStatsNotInTimeWindows_value,
                reporting="authnopriv",
            )

        if msg.engine_boots > local_engine_boots or (
            msg.engine_boots == local_engine_boots
            and msg.engine_time > latest_received_engine_time
        ):
            local.set_timing_values(
                boots=msg.engine_boots,
                time=msg.engine_time,
                latest_received_engine_time=msg.engine_time,
            )


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
