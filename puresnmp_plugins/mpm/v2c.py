"""
This module contains the definition for the community-based
message-processing model for SNMPv2
"""
from typing import Any, Awaitable, Callable, Dict, Optional, Union

from x690 import decode
from x690.types import Sequence

from puresnmp.credentials import V2C, Credentials
from puresnmp.pdu import PDU
from puresnmp.plugins.mpm import AbstractEncodingResult, MessageProcessingModel
from puresnmp.plugins.security import SecurityModel
from puresnmp.plugins.security import create as create_sm

IDENTIFIER = 1

TV2SecModel = SecurityModel[PDU, Sequence]


class V2CEncodingResult(AbstractEncodingResult):
    data: bytes
    security_model: Optional[TV2SecModel] = None


class V2CMPM(MessageProcessingModel[V2CEncodingResult, TV2SecModel]):
    """
    Message Processing Model for SNMP v2c
    """

    async def encode(
        self,
        request_id: int,
        credentials: Credentials,
        engine_id: bytes,
        context_name: bytes,
        pdu: PDU,
    ) -> V2CEncodingResult:
        if not isinstance(credentials, V2C):
            raise TypeError("SNMPv2c MPM should be used with V2C credentials!")

        security_model_id = 2
        if self.security_model is None:
            self.security_model = create_sm(security_model_id)

        packet = self.security_model.generate_request_message(
            pdu, b"", credentials
        )

        return V2CEncodingResult(bytes(packet))

    def decode(
        self,
        whole_msg: bytes,
        credentials: Credentials,
    ) -> PDU:
        """
        Convert an SNMPv2c message into a PDU instance
        """

        security_model_id = 2
        if self.security_model is None:
            self.security_model = create_sm(security_model_id)

        decoded, _ = decode(whole_msg, enforce_type=Sequence)

        msg = self.security_model.process_incoming_message(decoded, credentials)
        return msg


def create(
    transport_handler: Callable[[bytes], Awaitable[bytes]],
    lcd: Dict[str, Any],
) -> "MessageProcessingModel[V2CEncodingResult, Any]":
    """
    Creates a new instance of the V2C message-processing-model
    """
    return V2CMPM(transport_handler, lcd)
