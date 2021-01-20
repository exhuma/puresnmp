"""
This module contains the definition for the community-based
message-processing model for SNMPv2
"""
from typing import Any, Awaitable, Callable, Dict, cast

from x690 import decode
from x690.types import Integer, Null, OctetString, Sequence

from puresnmp.credentials import V2C, Credentials
from puresnmp.exc import SnmpError
from puresnmp.mpm import EncodingResult, MessageProcessingModel
from puresnmp.pdu import PDU

IDENTIFIER = 1


class V2CMPM(MessageProcessingModel):
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
    ) -> EncodingResult:
        if not isinstance(credentials, V2C):
            raise TypeError("SNMPv2c MPM should be used with V2C credentials!")
        # TODO we should delegate to the security model here to encode the
        #      community.
        packet = Sequence([Integer(1), OctetString(credentials.community), pdu])
        return EncodingResult(bytes(packet), None)

    def decode(
        self,
        whole_msg: bytes,
        credentials: Credentials,
    ) -> PDU:
        """
        The Message Processing Subsystem provides this service primitive for
        preparing the abstract data elements from an incoming SNMP message:
        """
        decoded, _ = decode(whole_msg, enforce_type=Sequence)
        # TODO we should delegate to the security model here to check the
        #      community
        if isinstance(decoded, Null):
            raise SnmpError(
                "Unable to construct a PDU from packet "
                f"with length {len(whole_msg)}"
            )
        return cast(PDU, decoded[2])


def create(
    transport_handler: Callable[[bytes], Awaitable[bytes]],
    lcd: Dict[str, Any],
) -> "MessageProcessingModel":
    """
    Creates a new instance of the V2C message-processing-model
    """
    return V2CMPM(transport_handler, lcd)
