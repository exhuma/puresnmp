"""
The message processing subsystem
"""
from dataclasses import dataclass
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    NamedTuple,
    Optional,
    Tuple,
    Type,
)

from x690.types import Integer, OctetString, Sequence, pop_tlv

from puresnmp.adt import HeaderData, Message, ScopedPDU, V3Flags
from puresnmp.credentials import V2C, V3, Credentials
from puresnmp.exc import SnmpError
from puresnmp.pdu import PDU, GetRequest
from puresnmp.security import (
    SecurityModel,
    UserSecurityModel,
    USMSecurityParameters,
)
from puresnmp.transport import TSender, get_request_id

MESSAGE_MAX_SIZE = 65507  # TODO determine a better value here


@dataclass(frozen=True)
class DiscoData:
    authoritative_engine_id: bytes
    authoritative_engine_boots: int
    authoritative_engine_time: int
    unknown_engine_ids: int


def is_confirmed(pdu: PDU):
    # XXX TODO This might be doable cleaner with subclassing in puresnmp.pdu
    return isinstance(pdu, GetRequest)


async def send_discovery_message(
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
        security_params,
        ScopedPDU(
            OctetString(),
            OctetString(),
            GetRequest(request_id, []),
        ),
    )
    payload = bytes(discovery_message)
    raw_response = await transport_handler(payload)
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
    disco: Optional[DiscoData]

    def __init_subclass__(cls: Type["MessageProcessingModel"]) -> None:
        MessageProcessingModel.__registry[cls.IDENTIFIER] = cls

    def __init__(
        self,
        transport_handler: Callable[[bytes], Awaitable[bytes]],
        lcd: Dict[str, Any],
    ) -> None:
        self.transport_handler = transport_handler
        self.lcd = lcd
        self.disco = None

    @staticmethod
    def create(
        identifier: int,
        transport_handler: Callable[[bytes], Awaitable[bytes]],
        lcd: Dict[str, Any],
    ) -> "MessageProcessingModel":
        """
        Creates a message processing model according to the given identifier.
        """
        # See https://tools.ietf.org/html/rfc3412#section-4.1.1
        if identifier not in MessageProcessingModel.__registry:
            raise UnknownMessageProcessingModel(identifier)
        return MessageProcessingModel.__registry[identifier](
            transport_handler, lcd
        )

    async def encode(
        self,
        request_id: int,
        credentials: Credentials,
        engine_id: bytes,
        context_name: bytes,
        pdu,
    ) -> bytes:
        raise NotImplementedError(
            "encode is not yet implemented in %r" % type(self)
        )

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
    ) -> bytes:
        raise NotImplementedError(
            "prepare_outgoing_message is not yet implemented in %r" % type(self)
        )

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
        raise NotImplementedError(
            "prepare_data_elements is not yet implemented in %r" % type(self)
        )


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

    async def encode(
        self,
        request_id: int,
        credentials: Credentials,
        engine_id: bytes,
        context_name: bytes,
        pdu,
    ) -> Tuple[bytes, Optional[SecurityModel]]:
        request_id
        engine_id
        context_name
        if not isinstance(credentials, V2C):
            raise TypeError("SNMPv2c MPM should be used with V2C credentials!")
        packet = Sequence(Integer(1), OctetString(credentials.community), pdu)
        return bytes(packet), None

    def decode(
        self,
        whole_msg,  # as received from the network
        credentials: Credentials,
        security_model: SecurityModel,
    ) -> PDU:
        """
        The Message Processing Subsystem provides this service primitive for
        preparing the abstract data elements from an incoming SNMP message:
        """
        decoded, _ = pop_tlv(whole_msg)
        return decoded[2]


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

    def decode(
        self,
        whole_msg,  # as received from the network
        credentials: Credentials,
        security_model: SecurityModel,
    ) -> PDU:
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

        msg = security_model.process_incoming_message(message, credentials)
        return msg.scoped_pdu.data

    async def encode(
        self,
        request_id: int,
        credentials: Credentials,
        engine_id: bytes,
        context_name: bytes,
        pdu,
    ) -> Tuple[bytes, SecurityModel]:
        """
        The Message Processing Subsystem provides this service primitive for
        preparing an outgoing SNMP Request or Notification Message:
        """

        if not isinstance(credentials, V3):
            raise TypeError("Credentials for SNMPv3 must be V3 instances!")

        security_model = SecurityModel.create(3)
        if not isinstance(security_model, UserSecurityModel):
            raise NotImplementedError(
                "Currently only USM is supported for SNMPv3"
            )

        # We need to determine some values from the remote host for security.
        # These can be retrieved by sending a so called discovery message.
        if not self.disco:
            self.disco = await send_discovery_message(self.transport_handler)
        security_engine_id = self.disco.authoritative_engine_id

        if engine_id == b"":
            engine_id = security_engine_id

        scoped_pdu = ScopedPDU(
            OctetString(engine_id), OctetString(context_name), pdu
        )
        flags = V3Flags(
            auth=credentials.auth is not None,
            priv=credentials.priv is not None,
            reportable=is_confirmed(pdu),
        )
        global_data = HeaderData(
            request_id,
            MESSAGE_MAX_SIZE,
            flags,
            security_model.IDENTIFIER,
        )

        if self.disco is not None:
            security_model.set_engine_timing(
                self.disco.authoritative_engine_id,
                self.disco.authoritative_engine_boots,
                self.disco.authoritative_engine_time,
            )

        msg = Message(Integer(3), global_data, None, scoped_pdu)
        output = security_model.generate_request_message(
            msg,
            security_engine_id,
            credentials,
        )

        outgoing_message = bytes(output)
        return outgoing_message, security_model


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
        raise NotImplementedError(
            "state_release is not yet implemented in %r" % type(self)
        )

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
