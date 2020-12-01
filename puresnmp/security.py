from dataclasses import dataclass
from typing import Any, Dict, Type, cast

from x690.types import Integer, OctetString, Sequence, pop_tlv

from puresnmp.adt import Message, V3Flags
from puresnmp.auth import Auth
from puresnmp.exc import InvalidSecurityModel, NotInTimeWindow, SnmpError


class UnsupportedSecurityLevel(SnmpError):
    """
    Raised on errors related to security levels
    """


class UnknownSecurityModel(SnmpError):
    def __init__(self, identifier: int) -> None:
        super().__init__(f"No security model with ID {identifier} found!")


@dataclass
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
        seq, _ = pop_tlv(data, enforce_type=Sequence)
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
        return Sequence(
            OctetString(self.authoritative_engine_id),
            Integer(self.authoritative_engine_boots),
            Integer(self.authoritative_engine_time),
            OctetString(self.user_name),
            OctetString(self.auth_params),
            OctetString(self.priv_params),
        )

    def pretty(self) -> str:
        """
        Return a value for CLI display
        """
        lines = [
            "Security Model #3",
            f" │ Engine ID   : {self.authoritative_engine_id!r}",
            f" │ Engine Boots: {self.authoritative_engine_boots}",
            f" │ Engine Time : {self.authoritative_engine_time}",
            f" │ Username    : {self.user_name!r}",
            f" │ Auth Params : {self.auth_params!r}",
            f" │ Priv Params : {self.priv_params!r}",
        ]
        return "\n".join(lines)


class SecurityModel:
    """
    Each Security Model defines the applied protecion on SNMP PDUs
    """

    IDENTIFIER: int

    #: The "Local Configuration Datastor" (LCD)
    local_config: Dict[bytes, Dict[str, Any]]

    __registry: Dict[int, Type["SecurityModel"]] = {}

    def __init_subclass__(cls: Type["SecurityModel"]) -> None:
        SecurityModel.__registry[cls.IDENTIFIER] = cls

    def __init__(self) -> None:
        self.local_config = {"users": {}}

    @staticmethod
    def create(identifier: int) -> "SecurityModel":
        """
        Creates a message processing model according to the given identifier.
        """
        if identifier not in SecurityModel.__registry:
            raise UnknownSecurityModel(identifier)
        return SecurityModel.__registry[identifier]()

    def generate_request_message(
        self,
        message: Message,
        security_engine_id: bytes,
        security_name: bytes,
        security_level: V3Flags,
    ) -> Message:
        raise NotImplementedError("Not yet implemented")


class UserSecurityModel(SecurityModel):
    IDENTIFIER = 3

    def authenticate_outgoing_message(self, auth_key, whole_msg):
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        return "authenticated_whole_message"  # XXX TODO

    def authenticate_incoming_message(self, auth_key, auth_params, whole_msg):
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        return "authenticated_whole_message"  # XXX TODO

    def encrypt_data(self, encrypt_key, data):
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        import pyDes

        des = pyDes.des(encrypt_key)
        encrypted = des.encrypt(data)
        return encrypted, "priv_params"  # XXX TODO priv-params

    def decrypt_data(self, decrypt_key, priv_params, data):
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        return "decrypted_data"  # XXX TODO

    def set_engine_timing(self, engine_id, boots, time):
        # TODO redundant with set_timing_values?
        engine_config = self.local_config[engine_id]
        engine_config["authoritative_engine_boots"] = boots
        engine_config["authoritative_engine_time"] = time

    def generate_request_message(
        self,
        message: Message,
        security_engine_id: bytes,
        security_name: bytes,
        security_level: V3Flags,
    ) -> Message:
        engine_config = self.local_config[security_engine_id]
        if security_name not in engine_config["users"]:
            # See https://tools.ietf.org/html/rfc3414#section-3.1
            # TODO better exception class
            raise SnmpError(f"Unknown User {security_name!r}")

        user_config = engine_config["users"][security_name]
        engine_boots = engine_config["authoritative_engine_boots"]
        engine_time = engine_config["authoritative_engine_time"]

        if security_level.priv and not all(
            [user_config["priv_proto"], user_config["auth_proto"]]
        ):
            raise UnsupportedSecurityLevel(
                f"Security level needs privacy, but either auth-proto or "
                f"priv-proto are missing for user {security_name!r}"
            )

        if security_level.priv:
            key = user_config["privkey"]
            try:
                encoded_pdu, priv_params = self.encrypt_data(
                    key, bytes(message.scoped_pdu)
                )
                # TODO: I could not understand what to do with this (from the rfc)
                #   > If the privacy module returns success, then the returned
                #   > privParameters are put into the msgPrivacyParameters field
                #   > of the securityParameters and the encryptedPDU serves as
                #   > the payload of the message being prepared.
            except Exception as exc:
                # TODO Use a proper app-exception here
                raise Exception("EncryptionError") from exc
        else:
            encoded_pdu = bytes(message.scoped_pdu)
            priv_params = b""

        auth_proto = Auth.create(user_config.get("auth_proto"))
        if security_level.auth and not auth_proto:
            raise UnsupportedSecurityLevel(
                f"Security level needs authentication, but auth-proto "
                f"is missing for user {security_name!r}"
            )
        if security_level.auth:
            try:
                auth_result = auth_proto.authenticate_outgoing_message(
                    user_config["auth_key"], encoded_pdu
                )
                encoded_pdu = auth_result.data
                auth_params = auth_result.auth_params
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
            OctetString(bytes(security_params)),
            encoded_pdu,
        )
        return secured_message

    def process_incoming_message(
        self,
        mp_model,
        msg_max_size,
        security_parameters,
        security_level,
        data,
    ):
        message_data, _ = pop_tlv(data)
        secparms = USMSecurityParameters.decode(message_data[2].pythonize())

        # TODO: Validate engine-id.
        # TODO: Validate incoming username against the request
        # See https://tools.ietf.org/html/rfc3414#section-3.2

        from pprint import pformat

        auth_key = localized_auth_key(
            user_auth_key, section.auth_engine_id, user_auth_algo
        )

        print(
            "\u001b[30;43m[debug-print-efa0]\u001b[0m\n%s" % pformat(locals())
        )  # XXX debug statement

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


@dataclass
class USMOld:  # XXX
    """
    A wrapper around Security Model #3 from SNMPv3

    See https://tools.ietf.org/html/rfc3414
    """

    engine_id: Integer
    engine_boots: Integer
    engine_time: Integer
    username: OctetString
    auth_params: OctetString
    privacy_params: OctetString

    @staticmethod
    def from_octet_string(data: OctetString) -> "USM":
        """
        Convert an X.690 Octet String into a Security Model
        """
        items_raw, _ = pop_tlv(data.pythonize())
        items = cast(Sequence, items_raw)
        if len(items) != 6:
            raise InvalidSecurityModel(
                "Invalid data to construct the security model."
            )
        return USM(
            items[0],  # type: ignore
            items[1],  # type: ignore
            items[2],  # type: ignore
            items[3],  # type: ignore
            items[4],  # type: ignore
            items[5],  # type: ignore
        )
