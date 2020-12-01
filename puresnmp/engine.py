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
from typing import Any, List, Set, Union
from uuid import UUID, uuid4

from x690.types import OctetString, Sequence, pop_tlv

from puresnmp.const import TransportDomain
from puresnmp.exc import SnmpError, UnknownMessageProcessingModel
from puresnmp.messageprocessing import MessageProcessingModel, PreparedData
from puresnmp.pdu import PDU
from puresnmp.security import SecurityModel

TAnyIp = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def generate_message_id() -> int:
    # TODO The number used for msgID should not have been used recently, and
    #      MUST NOT be the same as was used for any outstanding request.
    return 12345  # XXX TODO


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

    def send_bytes_to_net(self, ip: TAnyIp, packet: bytes) -> bytes:
        # XXX TODO refactor
        from puresnmp.transport import Transport

        tpt = Transport()
        return tpt.send(str(ip), 50009, packet)  # XXX expose hardcoded port

    def state_release(state_reference):
        """
        Release the memory that holds the referenced state information
        """
        raise NotImplementedError("Not Yet Implemented")

    def handle_incoming_message(
        self,
        data: bytes,
        transport_domain: TransportDomain,
        remote_addr: TAnyIp,
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
        prepared_data = mpm.prepare_data_elements(
            transport_domain,
            remote_addr,
            data,
        )
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
        transport_domain: TransportDomain,
        transport_address: Any,
        message_processing_model: int,
        security_model: SecurityModel,
        security_name: bytes,
        security_level: Any,
        context_engine_id: bytes,
        context_name: bytes,
        pdu_version: Any,
        pdu: Any,
        expect_response: bool,
    ) -> PDU:
        mpm = MessageProcessingModel.create(message_processing_model)
        message_id = generate_message_id()

        # TODO This could benefit from being more specific? Maybe? From the RFC:
        #  > If the contextEngineID is not yet determined, then the
        #  > contextEngineID is determined, in an implementation-dependent
        #  > manner, possibly using the transportDomain and
        #  > transportAddress.
        context_engine_id = (
            context_engine_id or f"{transport_domain}-{transport_address}"
        )

        # TODO This could benefit from being more specific? Maybe? From the RFC:
        #  > If the contextName is not yet determined, the contextName is
        #  > set to the default context.
        context_name = context_name or b""

        try:
            out_msg = mpm.prepare_outgoing_message(
                message_id,
                transport_domain,  # transport domain to be used
                transport_address,  # transport address to be used
                message_processing_model,  # typically, SNMP version
                security_model,  # Security Model to use
                OctetString(security_name),  # on behalf of this principal
                security_level,  # Level of Security requested
                OctetString(context_engine_id),  # data from/at this entity
                OctetString(context_name),  # data from/in this context
                pdu_version,  # the version of the PDU
                pdu,  # SNMP Protocol Data Unit
                expect_response,  # TRUE or FALSE
            )
        except:
            # TODO implement error-handling as in https://tools.ietf.org/html/rfc3412#section-7.1 subsection 3)
            raise
        if out_msg.transport_domain not in {
            TransportDomain.UDPIPV4,
            TransportDomain.UDPIPV6,
        }:
            raise SnmpError("Unsupported transport domain")
        response = self.send_bytes_to_net(
            out_msg.transport_address,
            out_msg.outgoing_message,
        )

        response_pdu = self.handle_incoming_message(
            response, out_msg.transport_domain, out_msg.transport_address
        )
        from puresnmp.pdu import Report

        return response_pdu

        # XXX Unreachable Code!!

        # XXX # TODO Handle errors as defined in
        # XXX #   https://tools.ietf.org/html/rfc3412#section-7.1 subsection 3)
        # XXX #   The "statusInformation" referenced in that section may be coming from
        # XXX #   an exception of "prepare_outgoing_message"

        # XXX # NOTE (RFC citation needed): The Report-PDU, Trapv2-PDU, and
        # XXX #   Response-PDU messages are considered Unconfirmed and the rest are
        # XXX #   Confirmed.
        # XXX if pdu.is_confirmed or pdu.is_notification:
        # XXX     # TODO The above checks could be done as "isinstance" checks?
        # XXX     # TODO Setting the engine ids is weird but following the RFC. I may
        # XXX     #      have misinterpreted this.
        # XXX     #      See https://tools.ietf.org/html/rfc3412#section-7.1 subsection 9)a)

        # XXX     target_engine_id = f"{dest_domain}-{dest_address}"
        # XXX     security_engine_id = target_entity_engine_id

        # XXX if pdu.is_confirmed:
        # XXX     state_reference = StateReference(
        # XXX         send_pdu_handle,
        # XXX         message_id,
        # XXX         snmp_engine_id,
        # XXX         security_model,
        # XXX         security_name,
        # XXX         security_level,
        # XXX         context_engine_id,
        # XXX         context_name,
        # XXX     )

        # XXX return ? <- According to RFC

        # XXX response, remote_domain, remote_ip = send_pdu_handle.send(out_msg)
        # XXX self.handle_incoming_message(response, remote_domain, remote_ip)
        # XXX return send_pdu_handle, dest_domain, dest_address

    def process_pdu(
        self,
        message_processing_model,  # typically, SNMP version
        security_model: SecurityModel,  # Security Model in use
        security_name,  # on behalf of this principal
        security_level,  # Level of Security
        context_engine_id,  # data from/at this SNMP entity
        context_name,  # data from/in this context
        pdu_ersion,  # the version of the PDU
        pdu,  # SNMP Protocol Data Unit
        max_size_response_scoped_pdu,  # maximum size of the Response PDU
        state_reference,  # reference to state information needed when sending a response
    ):
        """
        processes an incoming request/notification PDU
        """
        raise NotImplementedError(
            'puresnmp is currently only usable as SNMP "manager"'
        )

    def process_response_pdu(self, prepared_data: PreparedData) -> PDU:
        """
        Processes a response to a previously made request.
        """
        return prepared_data.pdu

    def register_context_engine_id(
        self, context_engine_ids: Set[UUID], pdu_types: Set[Any], app: Any
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
        self, context_engine_ids: Set[UUID], pdu_types: Set[Any]
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

    dispatcher: Dispatcher
    # XXX processing: MessageProcessingSubsystem
    security: SecuritySubsystem
    acs: AccessControlSubsystem

    engine_id: UUID
    known_contexts: Set[str]

    def __init__(self) -> None:
        self.engine_id = uuid4()
        self.known_contexts = set()
