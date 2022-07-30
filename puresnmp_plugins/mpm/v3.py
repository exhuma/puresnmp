"""
This module contains the implementation for the SNMPv3 message-processing model
"""
from typing import Any, Awaitable, Callable, Dict, Optional, Union

from x690.types import Integer, OctetString

from puresnmp.adt import (
    EncryptedMessage,
    HeaderData,
    Message,
    PlainMessage,
    ScopedPDU,
    V3Flags,
)
from puresnmp.credentials import V3, Credentials
from puresnmp.pdu import PDU, GetRequest
from puresnmp.plugins.mpm import AbstractEncodingResult, MessageProcessingModel
from puresnmp.plugins.security import SecurityModel
from puresnmp.plugins.security import create as create_sm
from puresnmp.transport import MESSAGE_MAX_SIZE

IDENTIFIER = 3


def is_confirmed(pdu: PDU) -> bool:
    """
    Return True if the given PDU instance expects a response.
    """
    # XXX TODO This might be doable cleaner with subclassing in puresnmp.pdu
    return isinstance(pdu, GetRequest)


TV3SecModel = SecurityModel[PlainMessage, Union[PlainMessage, EncryptedMessage]]


class V3EncodingResult(AbstractEncodingResult):
    """
    A simple data-structure representing the output for encoded messages
    """

    data: bytes
    security_model: Optional[TV3SecModel] = None


class V3MPM(MessageProcessingModel[V3EncodingResult, TV3SecModel]):
    """
    This class contains the concrete implementation for the v3
    message-processing-model.
    """

    def decode(
        self,
        whole_msg: bytes,  # as received from the network
        credentials: Credentials,
    ) -> PDU:
        security_model_id = 3
        if self.security_model is None:
            self.security_model = create_sm(security_model_id)
        message = Message.decode(whole_msg)
        msg = self.security_model.process_incoming_message(message, credentials)
        return msg.scoped_pdu.data

    async def encode(
        self,
        request_id: int,
        credentials: Credentials,
        engine_id: bytes,
        context_name: bytes,
        pdu: PDU,
    ) -> V3EncodingResult:

        if not isinstance(credentials, V3):
            raise TypeError("Credentials for SNMPv3 must be V3 instances!")

        security_model_id = 3
        if self.security_model is None:
            self.security_model = create_sm(security_model_id)

        # We need to determine some values from the remote host for security.
        # These can be retrieved by sending a so called discovery message.
        if not self.disco:
            self.disco = await self.security_model.send_discovery_message(
                self.transport_handler
            )
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
        header = HeaderData(
            request_id,
            MESSAGE_MAX_SIZE,
            flags,
            security_model_id,
        )

        if self.disco is not None:
            self.security_model.set_engine_timing(
                self.disco.authoritative_engine_id,
                self.disco.authoritative_engine_boots,
                self.disco.authoritative_engine_time,
            )

        snmp_version = 3
        msg = PlainMessage(Integer(snmp_version), header, b"", scoped_pdu)
        output = self.security_model.generate_request_message(
            msg,
            security_engine_id,
            credentials,
        )

        outgoing_message = bytes(output)
        return V3EncodingResult(outgoing_message, self.security_model)


def create(
    transport_handler: Callable[[bytes], Awaitable[bytes]],
    lcd: Dict[str, Any],
) -> "MessageProcessingModel[V3EncodingResult, TV3SecModel]":
    """
    Creates a new instance of the V3 message-processing-model
    """
    return V3MPM(transport_handler, lcd)
