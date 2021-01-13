from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from x690.types import Integer, OctetString, Sequence, pop_tlv

from puresnmp.credentials import V2C, Credentials
from puresnmp.mpm import MessageProcessingModel
from puresnmp.pdu import PDU
from puresnmp.security import SecurityModel

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


def create(
    transport_handler: Callable[[bytes], Awaitable[bytes]],
    lcd: Dict[str, Any],
) -> "MessageProcessingModel":
    return V2CMPM(transport_handler, lcd)
