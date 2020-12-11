"""
Implementation of an SNMP engine according to RFC-3411
======================================================

Deviations from the RFC
-----------------------

* There is no app-registration (hence, also no "pdu-handle"). This simplifies
  the overall design by removing the support for multiple "applications". In
  the eyes of the author of this library, this is a rare use-case. If the need
  arises this should still be fairly easy to implement later by following the
  RFCs for app-registration and using a "pduHandle"


Scenario-Diagram (see rfc:`3411`)
---------------------------------

This diagram shows how a Command Generator or Notification Originator
application requests that a PDU be sent, and how the response is returned
(asynchronously) to that application::

    Command           Dispatcher               Message           Security
    Generator            |                     Processing           Model
    |                    |                     Model                    |
    |      sendPdu       |                        |                     |
    |------------------->|                        |                     |
    |                    | prepareOutgoingMessage |                     |
    :                    |----------------------->|                     |
    :                    |                        | generateRequestMsg  |
    :                    |                        |-------------------->|
    :                    |                        |                     |
    :                    |                        |<--------------------|
    :                    |                        |                     |
    :                    |<-----------------------|                     |
    :                    |                        |                     |
    :                    |------------------+     |                     |
    :                    | Send SNMP        |     |                     |
    :                    | Request Message  |     |                     |
    :                    | to Network       |     |                     |
    :                    |                  v     |                     |
    :                    :                  :     :                     :
    :                    :                  :     :                     :
    :                    :                  :     :                     :
    :                    |                  |     |                     |
    :                    | Receive SNMP     |     |                     |
    :                    | Response Message |     |                     |
    :                    | from Network     |     |                     |
    :                    |<-----------------+     |                     |
    :                    |                        |                     |
    :                    |   prepareDataElements  |                     |
    :                    |----------------------->|                     |
    :                    |                        | processIncomingMsg  |
    :                    |                        |-------------------->|
    :                    |                        |                     |
    :                    |                        |<--------------------|
    :                    |                        |                     |
    :                    |<-----------------------|                     |
    | processResponsePdu |                        |                     |
    |<-------------------|                        |                     |
    |                    |                        |                     |
"""
import ipaddress
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Union

from x690.types import Null, OctetString, Sequence, pop_tlv

import puresnmp.pdu as pdu
from puresnmp.adt import V3Flags
from puresnmp.exc import SnmpError, UnknownMessageProcessingModel
from puresnmp.messageprocessing import (
    MessageProcessingModel,
    PreparedData,
)
from puresnmp.pdu import PDU
from puresnmp.security import SecurityModel
from puresnmp.transport import Transport, get_request_id

TAnyIp = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
TTransportHandler = Callable[[TAnyIp, int, bytes], bytes]

UDPTransport = Transport()
udp_handler = UDPTransport.send


def generate_engine_id_ip(pen: int, ip: TAnyIp) -> bytes:
    buffer = bytearray(pen.to_bytes(4, "big"))
    fmt = 1 if ip.version == 4 else 2
    buffer.append(fmt)
    buffer.extend(ip.packed)
    return bytes(buffer)


def generate_engine_id_mac(pen: int, mac_address: str) -> bytes:
    if "-" in mac_address:
        octets = [bytes.fromhex(oct) for oct in mac_address.split("-")]
    else:
        octets = [bytes.fromhex(oct) for oct in mac_address.split(":")]
    buffer = bytearray(pen.to_bytes(4, "big"))
    buffer.append(3)
    buffer.extend(octets)
    return bytes(buffer)


def generate_engine_id_text(pen: int, text: str) -> bytes:
    if len(text) > 27:
        raise SnmpError(
            "Invalid engine ID. Text must have fewer than 27 characters"
        )
    buffer = bytearray(pen.to_bytes(4, "big"))
    buffer[0] = 1
    buffer.append(4)
    buffer.extend(text.encode("ascii"))
    return bytes(buffer)


def generate_engine_id_octets(pen: int, octets: bytes) -> bytes:
    if len(octets) > 27:
        raise SnmpError(
            f"Invalid engine ID. The value {octets!r} is longer than 27 octets"
        )
    buffer = bytearray(pen.to_bytes(4, "big"))
    buffer.append(5)
    buffer.extend(octets)
    return bytes(buffer)


@dataclass
class Credentials:
    SECURITY_MODEL_ID = -1
    community: str = ""
    username: str = ""
    auth_key: bytes = b""
    auth_mode: str = ""
    encryption_key: bytes = b""
    encryption_mode: str = ""

    @staticmethod
    def as_flags() -> V3Flags:
        raise NotImplementedError("Not yet implemented")


class CommunityString(Credentials):
    SECURITY_MODEL_ID = 2

    def __init__(self, community: str) -> None:
        self.community = community

    @staticmethod
    def as_flags() -> V3Flags:
        return V3Flags(False, False, False)


class NoAuthNoPriv(Credentials):
    SECURITY_MODEL_ID = 3

    def __init__(self, username: str) -> None:
        self.username = username

    @staticmethod
    def as_flags() -> V3Flags:
        return V3Flags(False, False, False)


class AuthNoPriv(Credentials):
    SECURITY_MODEL_ID = 3

    def __init__(self, username: str, auth_key: bytes, auth_mode: str) -> None:
        self.username = username
        self.auth_key = auth_key
        self.auth_mode = auth_mode

    @staticmethod
    def as_flags() -> V3Flags:
        return V3Flags(True, False, False)


class AuthPriv(Credentials):
    SECURITY_MODEL_ID = 3

    def __init__(
        self,
        username: str,
        auth_key: bytes,
        auth_mode: str,
        encryption_key: bytes,
        encryption_mode: str,
    ) -> None:
        self.username = username
        self.auth_key = auth_key
        self.auth_mode = auth_mode
        self.encryption_key = encryption_key
        self.encryption_mode = encryption_mode

    @staticmethod
    def as_flags() -> V3Flags:
        return V3Flags(True, True, False)


class ErrorIndication:
    """
    Details of an error during processing
    """


class SecurityProtocol:
    """
    A Security Protocol specifies the mechanisms, procedures, and MIB objects
    used to provide a security service such as authentication or privacy.
    """


class AccessControlModel:
    """
    An Access Control Model defines a particular access decision function in
    order to support decisions regarding access rights.
    """


class AccessControlSubsystem:
    """
    The Access Control Subsystem provides authorization services by means of
    one or more Access Control Models.
    """

    # TODO Every message has an associated securityLevel.  All Subsystems
    #     (Message Processing, Security, Access Control) and applications are
    #     REQUIRED to either supply a value of securityLevel or to abide by the
    #     supplied value of securityLevel while processing the message and its
    #     contents.

    models: List[AccessControlModel]

    def is_access_allowed(
        self,
        security_model: SecurityModel,  # Security Model in use
        security_name,  # principal who wants to access
        security_level,  # Level of Security
        view_type,  # read, write, or notify view
        context_name,  # context containing variableName
        variable_name,  # OID for the managed object
    ) -> bool:
        raise NotImplementedError("Not yet implemented")


class SecuritySubsystem:
    """
    The Security Subsystem provides security services such as the
    authentication and privacy of messages and potentially contains multiple
    Security Models as shown in the following figure

    One or more Security Models may be present.
    """

    # TODO Every message has an associated securityLevel.  All Subsystems
    #     (Message Processing, Security, Access Control) and applications are
    #     REQUIRED to either supply a value of securityLevel or to abide by the
    #     supplied value of securityLevel while processing the message and its
    #     contents.

    models: List[SecurityModel]

    def generate_request_msg(
        message_processing_model,  # typically, SNMP version
        global_data,  # message header, admin data
        max_message_size,  # of the sending SNMP entity
        security_model: SecurityModel,  # for the outgoing message
        security_engine_id,  # authoritative SNMP entity
        security_name,  # on behalf of this principal
        security_level,  # Level of Security requested
        scoped_pdu,  # message (plaintext) payload
    ):
        """
        The Security Subsystem provides the following primitive to generate a
        Request or Notification message:
        """
        return (
            security_parameters,  # filled in by Security Module
            whole_msg,  # complete generated message
            whole_msg_length,  # length of the generated message
        )

    def process_incoming_msg(
        message_processing_model,  # typically, SNMP version
        max_message_size,  # of the sending SNMP entity
        security_parameters,  # for the received message
        security_model: SecurityModel,  # for the received message
        security_level,  # Level of Security
        whole_msg,  # as received on the wire
        whole_msg_length,  # length as received on the wire
    ):
        """
        The Security Subsystem provides the following primitive to process an
        incoming message:
        """

        return (
            security_engine_id,  # authoritative SNMP entity
            security_name,  # identification of the principal
            scoped_pdu,  # message (plaintext) payload
            max_size_response_scoped_pdu,  # maximum size sender can handle
            security_state_reference,  # reference to security state information, needed for response
        )

    def generate_response_msg(
        message_processing_model,  # typically, SNMP version
        global_data,  # message header, admin data
        max_message_size,  # of the sending SNMP entity
        security_model: SecurityModel,  # for the outgoing message
        security_engine_id,  # authoritative SNMP entity
        security_name,  # on behalf of this principal
        security_level,  # for the outgoing message
        scoped_pdu,  # message (plaintext) payload
        security_state_reference,  # reference to security state information from original request
    ):
        """
        The Security Subsystem provides the following primitive to generate a
        Response message:
        """
        return (
            security_parameters,  # filled in by Security Module
            whole_msg,  # complete generated message
            whole_msg_length,  # length of the generated message
        )


class Dispatcher:
    """
    There is only one Dispatcher in an SNMP engine.  It allows for concurrent
    support of multiple versions of SNMP messages in the SNMP engine.  It does
    so by:

      * sending and receiving SNMP messages to/from the network,
      * determining the version of an SNMP message and interacting with the
        corresponding Message Processing Model,
      * providing an abstract interface to SNMP applications for delivery of a
        PDU to an application.
      * providing an abstract interface for SNMP applications that allows them
        to send a PDU to a remote SNMP entity.
    """

    def __init__(self):
        self.registered_apps = {}
        self.counters = {}

    def increase_counter(self, name: str) -> None:
        if name not in self.counters:
            self.counters[name] = 1
        else:
            self.counters[name] += 1

    def state_release(state_reference):
        """
        Release the memory that holds the referenced state information
        """
        raise NotImplementedError("Not Yet Implemented")

    def handle_incoming_message(
        self,
        data: bytes,
        security_model: SecurityModel,
    ) -> PDU:
        """
        Processes an incomning SNMP message.
        """
        # See https://tools.ietf.org/html/rfc3412#section-4.2.1
        self.increase_counter("snmpInPkts")
        try:
            version = pop_tlv(data, enforce_type=Sequence)[0][0].value
        except Exception as exc:
            self.increase_counter("snmpInASNParseErrs")
            # TODO use proper exception
            raise Exception(
                "Unable to determine SNMP version in packet"
            ) from exc
        try:
            mpm = MessageProcessingModel.create(version)
        except UnknownMessageProcessingModel:
            self.increase_counter("snmpInBadVersions")
            raise
        prepared_data = mpm.prepare_data_elements(data, security_model)
        return self.dispatch_incoming_message(prepared_data)

    def dispatch_incoming_message(self, prepared_data: PreparedData) -> PDU:
        """
        Corresponds to https://tools.ietf.org/html/rfc3412#section-4.2.2
        """
        # TODO if send_pdu_handle is None:
        # TODO     return self.dispatch_request(prepared_data)
        return self.process_response_pdu(prepared_data)

    def dispatch_request(self, prepared_data: PreparedData) -> None:
        """
        See https://tools.ietf.org/html/rfc3412#section-4.2.2.1
        """
        raise NotImplementedError(
            "Processing requests or notifications is not yet implemented"
        )

    def send_pdu(
        self,
        transport_address: TAnyIp,
        transport_port: int,
        message_processing_model: int,
        security_model: SecurityModel,
        security_name: bytes,
        security_level: Any,
        context_engine_id: bytes,
        context_name: bytes,
        pdu_version: Any,
        pdu: Any,
        expect_response: bool,
        transport_handler: Optional[TTransportHandler] = None,
    ) -> PDU:

        if transport_handler is None:
            transport_handler = udp_handler

        mpm = MessageProcessingModel.create(message_processing_model)
        message_id = get_request_id()

        # TODO This could benefit from being more specific? Maybe? From the RFC:
        #  > If the contextName is not yet determined, the contextName is
        #  > set to the default context.
        context_name = context_name or b""

        def inner_transport_handler(data: bytes) -> bytes:
            output = transport_handler(transport_address, transport_port, data)
            return output

        try:
            out_msg = mpm.prepare_outgoing_message(
                message_id,
                security_model,  # Security Model to use
                OctetString(security_name),  # on behalf of this principal
                security_level,  # Level of Security requested
                OctetString(context_engine_id),  # data from/at this entity
                OctetString(context_name),  # data from/in this context
                pdu_version,  # the version of the PDU
                pdu,  # SNMP Protocol Data Unit
                expect_response,  # TRUE or FALSE
                inner_transport_handler,
            )
        except:
            # TODO implement error-handling as in https://tools.ietf.org/html/rfc3412#section-7.1 subsection 3)
            raise

        response = inner_transport_handler(out_msg)
        response_pdu = self.handle_incoming_message(response, security_model)

        # XXX # TODO Handle errors as defined in
        # XXX #   https://tools.ietf.org/html/rfc3412#section-7.1 subsection 3)
        # XXX #   The "statusInformation" referenced in that section may be coming from
        # XXX #   an exception of "prepare_outgoing_message"

        return response_pdu

    def process_response_pdu(self, prepared_data: PreparedData) -> PDU:
        """
        Processes a response to a previously made request.
        """
        return prepared_data.pdu

    def register_context_engine_id(
        self, context_engine_ids: Set[bytes], pdu_types: Set[Any], app: Any
    ) -> None:
        """
        Applications can register/unregister responsibility for a specific
        contextEngineID, for specific pduTypes, with the PDU Dispatcher
        according to the following primitives.  The list of particular pduTypes
        that an application can register for is determined by the Message
        Processing Model(s) supported by the SNMP entity that contains the PDU
        Dispatcher.
        """
        for cid in context_engine_ids:
            context_apps = self.registered_apps.setdefault(cid, {})
            for ptype in pdu_types:
                if ptype in context_apps:
                    # TODO Better exception
                    raise Exception("RFC Error: alreadyRegistered")
                context_apps[ptype] = app

    def unregister_context_engine_id(
        self, context_engine_ids: Set[bytes], pdu_types: Set[Any]
    ) -> None:
        """
        Applications can register/unregister responsibility for a specific
        contextEngineID, for specific pduTypes, with the PDU Dispatcher
        according to the following primitives.  The list of particular pduTypes
        that an application can register for is determined by the Message
        Processing Model(s) supported by the SNMP entity that contains the PDU
        Dispatcher.
        """
        for cid in context_engine_ids:
            context_apps = self.registered_apps.setdefault(cid, {})
            for ptype in pdu_types:
                context_apps.pop(ptype, None)


class Engine:
    """
    An SNMP engine provides services for sending and receiving messages,
    authenticating and encrypting messages, and controlling access to managed
    objects.  There is a one-to-one association between an SNMP engine and the
    SNMP entity which contains it.

    The engine contains:

      * a Dispatcher,
      * a Message Processing Subsystem,
      * a Security Subsystem, and
      * an Access Control Subsystem.
    """

    engine_id: bytes
    context_name: bytes
    dispatcher: Dispatcher
    mpm: MessageProcessingModel
    security: Dict[int, SecurityModel]

    def __init__(
        self,
        engine_id: bytes,
        context_name: bytes,
        transport_handler: Callable[..., bytes],
    ) -> None:
        self.engine_id = engine_id
        self.dispatcher = Dispatcher()
        self.mpm = MessageProcessingModel()
        self.security = {}
        self.context_name = context_name
        self.transport_handler = transport_handler

    def get(
        self,
        ip: TAnyIp,
        port: int,
        oid: str,
        version: int,
        creds: Credentials,
    ) -> Any:

        protomap = {
            "md5": "usmHMACMD5AuthProtocol",
            "sha1": "usmHMACSHAAuthProtocol",
            "des": "usmDESPrivProtocol",
        }
        auth = {
            creds.username.encode("ascii"): {
                "auth_proto": protomap[creds.auth_mode],
                "auth_key": creds.auth_key,
                "priv_proto": protomap[creds.encryption_mode],
                "priv_key": creds.encryption_key,
            }
        }
        if creds.SECURITY_MODEL_ID not in self.security:
            security = SecurityModel.create(creds.SECURITY_MODEL_ID)
            security.set_default_auth(auth)
            self.security[creds.SECURITY_MODEL_ID] = security
        else:
            security = self.security[creds.SECURITY_MODEL_ID]

        flags = creds.as_flags()

        embedded_pdu = pdu.GetRequest(
            get_request_id(), pdu.VarBind(oid, Null())
        )
        response = self.dispatcher.send_pdu(
            ip,
            port,
            version,
            security_model=security,
            security_name=creds.username.encode("ascii"),
            security_level=flags,
            context_engine_id=self.engine_id,
            context_name=self.context_name,
            pdu_version=None,
            pdu=embedded_pdu,
            expect_response=False,
            transport_handler=self.transport_handler,
        )

        return response.varbinds[0].value
