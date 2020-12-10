"""
The message processing subsystem
"""
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Dict, List, NamedTuple, Tuple, Type, Union, Callable

from x690.types import Integer, OctetString, Sequence, pop_tlv

from puresnmp.adt import HeaderData, Message, ScopedPDU, V3Flags
from puresnmp.const import TransportDomain
from puresnmp.exc import SnmpError
from puresnmp.pdu import PDU, GetRequest
from puresnmp.security import (
    SecurityModel,
    UserSecurityModel,
    USMSecurityParameters,
)
from puresnmp.types import Counter
from puresnmp.typevars import TAnyIp

MESSAGE_MAX_SIZE = 65507  # TODO determine a better value here


@dataclass
class DiscoData:
    authoritative_engine_id: bytes
    authoritative_engine_boots: int
    authoritative_engine_time: int
    unknown_engine_ids: int


def get_request_id() -> int:
    # XXX The number used for msgID should not have been used recently, and
    # XXX MUST NOT be the same as was used for any outstanding request.
    return 12345  # XXX don't hardcode this


def is_confirmed(pdu: PDU):
    # XXX TODO This might be doable cleaner with subclassing in puresnmp.pdu
    return isinstance(pdu, GetRequest)


def send_auth_discovery_message(
    transport_domain: TransportDomain, transport_address: TAnyIp
) -> DiscoData:
    # Via https://tools.ietf.org/html/rfc3414#section-4
    #
    # If authenticated communication is required, then the discovery
    # process should also establish time synchronization with the
    # authoritative SNMP engine. This may be accomplished by sending an
    # authenticated Request message with the value of
    # msgAuthoritativeEngineID set to the newly learned snmpEngineID and
    # with the values of msgAuthoritativeEngineBoots and
    # msgAuthoritativeEngineTime set to zero. For an authenticated Request
    # message, a valid userName must be used in the msgUserName field. The
    # response to this authenticated message will be a Report message
    # containing the up to date values of the authoritative SNMP engine's
    # snmpEngineBoots and snmpEngineTime as the value of the
    # msgAuthoritativeEngineBoots and msgAuthoritativeEngineTime fields
    # respectively. It also contains the usmStatsNotInTimeWindows counter
    # in the varBindList of the Report PDU. The time synchronization then
    # happens automatically as part of the procedures in section 3.2 step
    # 7b. See also section 2.3.
    raise NotImplementedError("Not yet implemented")


def send_discovery_message(
    transport_handler: Callable[[bytes], bytes]
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
        security_params,
        ScopedPDU(
            OctetString(),
            OctetString(),
            GetRequest(request_id, []),
        ),
    )
    payload = bytes(discovery_message)
    raw_response = transport_handler(payload)
    response, _ = pop_tlv(raw_response, Sequence)

    response_msg = Message.from_sequence(response)

    response_id = response_msg.scoped_pdu.data.request_id
    if response_id != request_id:
        raise SnmpError(
            f"Invalid response ID {response_id} for request id {request_id}"
        )

    # The engine-id is available in two places: The response directly, and also
    # the Report PDU. In initial tests these values were identical, and
    # fetching them from the wrapping message would be easier. But because the
    # RFC explicitly states that it's the value from inside the PDU I picked it
    # out from there instead.
    auth_security_params = response_msg.security_parameters
    unknown_engine_ids = response_msg.scoped_pdu.data.varbinds[
        0
    ].value.pythonize()

    out = DiscoData(
        authoritative_engine_id=auth_security_params.authoritative_engine_id,
        authoritative_engine_boots=auth_security_params.authoritative_engine_boots,
        authoritative_engine_time=auth_security_params.authoritative_engine_time,
        unknown_engine_ids=unknown_engine_ids,
    )
    return out


class PreparedData(NamedTuple):
    security_model: SecurityModel
    security_name: bytes
    security_level: "V3Flags"
    context_engine_id: bytes
    context_name: bytes
    pdu_version: int
    pdu: PDU
    pdu_type: int
    max_size_response_scoped_pdu: int
    status_information: int
    state_reference: Any


class MPMException(SnmpError):
    """
    Base class for message-processing model related errors
    """


class UnknownMessageProcessingModel(MPMException):
    """
    Exception which is raised when working with an unsupported/unknown
    message-processing model
    """

    def __init__(self, identifier: int) -> None:
        super().__init__(
            f"Unknown message processing model with ID: {identifier}"
        )


class MessageProcessingModel:
    """
    Each Message Processing Model defines the format of a particular version of
    an SNMP message and coordinates the preparation and extraction of each such
    version-specific message format.

    See https://tools.ietf.org/html/rfc3411#section-6.2
    """

    IDENTIFIER: int
    __registry: Dict[int, Type["MessageProcessingModel"]] = {}

    def __init_subclass__(cls: Type["MessageProcessingModel"]) -> None:
        MessageProcessingModel.__registry[cls.IDENTIFIER] = cls

    @staticmethod
    def create(identifier: int) -> "MessageProcessingModel":
        """
        Creates a message processing model according to the given identifier.
        """
        # See https://tools.ietf.org/html/rfc3412#section-4.1.1
        if identifier not in MessageProcessingModel.__registry:
            raise UnknownMessageProcessingModel(identifier)
        return MessageProcessingModel.__registry[identifier]()

    def prepare_outgoing_message(
        self,
        message_id: int,
        security_model: SecurityModel,  # Security Model to use
        security_name,  # on behalf of this principal
        security_level,  # Level of Security requested
        context_engine_id,  # data from/at this entity
        context_name,  # data from/in this context
        pdu_version,  # the version of the PDU
        pdu,  # SNMP Protocol Data Unit
        expect_response,  # TRUE or FALSE
        transport_handler: Callable[[bytes], bytes],
    ) -> bytes:
        raise NotImplementedError("This needs to be overridden in a subclass")

    def prepare_data_elements(
        self,
        whole_msg,  # as received from the network
        security_model: SecurityModel,
    ) -> PreparedData:
        """
        The Message Processing Subsystem provides this service primitive for
        preparing the abstract data elements from an incoming SNMP message:
        """
        # XXX TODO should raise "SnmpFailure" on error
        raise NotImplementedError("This needs to be overridden in a subclass")


class SNMPV1_MPM(MessageProcessingModel):
    """
    Message Processing Model for SNMPv1
    """

    IDENTIFIER = 0


class SNMPV2C_MPM(MessageProcessingModel):
    """
    Message Processing Model for SNMP v2c
    """

    IDENTIFIER = 1


class SNMPV2X_MPM(MessageProcessingModel):
    """
    Message Processing Model for SNMP v2*
    """

    IDENTIFIER = 2


class SNMPV3_MPM(MessageProcessingModel):
    """
    Message Processing Model for SNMP v3
    """

    IDENTIFIER = 3

    def prepare_data_elements(
        self,
        whole_msg,  # as received from the network
        security_model: SecurityModel,
    ) -> PreparedData:
        """
        The Message Processing Subsystem provides this service primitive for
        preparing the abstract data elements from an incoming SNMP message:
        """
        message = Message.decode(whole_msg)
        security_level = message.global_data.flags
        security_params = message.security_parameters

        if security_params is None:
            raise NotImplementedError(
                "Messages without security params are not yet supported"
            )

        if isinstance(message.scoped_pdu, bytes):
            raise NotImplementedError(
                "Encrypted messages are not yet supported"
            )

        msg = security_model.process_incoming_message(message)

        return PreparedData(
            security_model,  # Security Model to use
            security_params.user_name,  # on behalf of this principal
            security_level,  # Level of Security requested
            security_params.authoritative_engine_id,  # data from/at this entity
            message.scoped_pdu.context_name,  # data from/in this context
            -1,  # XXX # the version of the PDU
            message.scoped_pdu.data,  # SNMP Protocol Data Unit
            -1,  # XXX # SNMP PDU type
            message.global_data.message_max_size,  # maximum size sender can accept
            None,  # XXX status_information,  # success or errorIndication error counter OID/value if error
            None,  # XXX state_reference,  # reference to state information to be used for possible Response
        )

    def prepare_outgoing_message(
        self,
        message_id: int,
        security_model: SecurityModel,  # Security Model to use
        security_name: OctetString,  # on behalf of this principal
        security_level: V3Flags,  # Level of Security requested
        context_engine_id: OctetString,  # data from/at this entity
        context_name: OctetString,  # data from/in this context
        pdu_version: int,  # the version of the PDU
        pdu: PDU,  # SNMP Protocol Data Unit
        expect_response: bool,  # TRUE or FALSE
        transport_handler: Callable[[bytes], bytes],
    ) -> bytes:
        """
        The Message Processing Subsystem provides this service primitive for
        preparing an outgoing SNMP Request or Notification Message:
        """
        # SNMPv3 does not use "expect_response" nor "pdu_version". We drop it
        # in the code here to silence pylint's unused variable check
        expect_response  # pylint: disable=pointless-statement
        pdu_version  # pylint: disable=pointless-statement

        security = security_model
        disco = None
        auth_disco = None
        if isinstance(security_model, UserSecurityModel):
            disco = send_discovery_message(transport_handler)
            if security_level.auth:
                auth_disco = send_auth_discovery_message(
                    transport_domain, transport_address
                )
            security_engine_id = disco.authoritative_engine_id

        scoped_pdu = ScopedPDU(context_engine_id, context_name, pdu)
        global_data = HeaderData(
            message_id,
            MESSAGE_MAX_SIZE,
            V3Flags(
                auth=security_level.auth,
                priv=security_level.priv,
                reportable=is_confirmed(pdu),
            ),
            security.IDENTIFIER,
        )

        security_model.set_engine_timing(
            disco.authoritative_engine_id,
            disco.authoritative_engine_boots,
            disco.authoritative_engine_time,
        )

        msg = Message(Integer(3), global_data, None, scoped_pdu)
        output = security.generate_request_message(
            msg,
            security_engine_id,
            security_name.value,
            security_level,
        )
        # TODO this may need some cleanup. Kept it this way to be aligned with
        #      the RFC var-names
        outgoing_message = bytes(output)
        return outgoing_message


class MessageProcessingSubsystem:
    """
    The Message Processing Subsystem is responsible for preparing messages for
    sending, and extracting data from received messages.

    The Message Processing Subsystem potentially contains multiple Message
    Processing Models as shown in the next figure.

    One or more Message Processing Models may be present.
    """

    # TODO Every message has an associated securityLevel.  All Subsystems
    #     (Message Processing, Security, Access Control) and applications are
    #     REQUIRED to either supply a value of securityLevel or to abide by the
    #     supplied value of securityLevel while processing the message and its
    #     contents.

    models: List[MessageProcessingModel]

    def state_release(state_reference):
        """
        Release the memory that holds the referenced state information
        """
        raise NotImplementedError("Not Yet Implemented")

    def prepare_response_message(
        self,
        security_model,  # same as on incoming request
        security_name,  # same as on incoming request
        security_level,  # same as on incoming request
        context_engine_id,  # data from/at this SNMP entity
        context_name,  # data from/in this context
        pdu_version,  # the version of the PDU
        pdu,  # SNMP Protocol Data Unit
        max_size_response_scoped_pdu,  # maximum size able to accept
        state_reference,  # reference to state information as presented with the request
        status_information,  # success or errorIndication error counter OID/value if error
    ) -> Tuple[Any, Any, Any, Any]:
        """
        The Message Processing Subsystem provides this service primitive for
        preparing an outgoing SNMP Response Message:
        """
        return (
            dest_transport_domain,  # destination transport domain
            dest_transport_address,  # destination transport address
            outgoing_message,  # the message to send
            outgoing_message_length,  # its length
        )