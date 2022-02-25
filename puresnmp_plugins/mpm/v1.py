"""
This module provides the plugin for SNMPv1 message processing
"""
from typing import Any, Awaitable, Callable, Dict, Optional
from warnings import warn

from x690 import decode
from x690.types import Sequence

from puresnmp.credentials import V1, Credentials
from puresnmp.pdu import PDU
from puresnmp.plugins.mpm import AbstractEncodingResult, MessageProcessingModel
from puresnmp.plugins.security import SecurityModel
from puresnmp.plugins.security import create as create_sm

IDENTIFIER = 0


TV1SecModel = SecurityModel[PDU, Sequence]


class V1EncodingResult(AbstractEncodingResult):
    data: bytes
    security_model: Optional[TV1SecModel] = None


class V1MPM(MessageProcessingModel[V1EncodingResult, TV1SecModel]):
    """
    Message Processing Model for SNMPv1
    """

    async def encode(
        self,
        request_id: int,
        credentials: Credentials,
        engine_id: bytes,
        context_name: bytes,
        pdu: PDU,
    ) -> V1EncodingResult:
        if not isinstance(credentials, V1):
            raise TypeError("SNMPv1 MPM should be used with V1 credentials!")

        # The SNMPv1 support is blatantly ripping off the SNMPv2c
        # implementation which is *mostly* equivalent. Once the distinctions
        # have been ironed out, this warning can be removed.
        warn("Experimental SNMPv1 support", UserWarning)

        security_model_id = 1
        if self.security_model is None:
            self.security_model = create_sm(security_model_id)

        packet = self.security_model.generate_request_message(
            pdu, b"", credentials
        )

        return V1EncodingResult(bytes(packet))

    def decode(
        self,
        whole_msg: bytes,
        credentials: Credentials,
    ) -> PDU:
        """
        Convert an SNMPv2c message into a PDU instance
        """

        # The SNMPv1 support is blatantly ripping off the SNMPv2c
        # implementation which is *mostly* equivalent. Once the distinctions
        # have been ironed out, this warning can be removed.
        warn("Experimental SNMPv1 support", UserWarning)

        security_model_id = 1
        if self.security_model is None:
            self.security_model = create_sm(security_model_id)

        decoded, _ = decode(whole_msg, enforce_type=Sequence)
        _, _, pdu = decoded

        # Because PDUs are lazy, we need to trigger the readout of the PDU
        # value. Otherwise, any error-response is hidden, causing cryptic
        # errors.
        pdu.value

        msg = self.security_model.process_incoming_message(decoded, credentials)
        return msg


def create(
    transport_handler: Callable[[bytes], Awaitable[bytes]],
    lcd: Dict[str, Any],
) -> MessageProcessingModel[V1EncodingResult, TV1SecModel]:
    """
    Creates a new instance for V1 message processing
    """
    return V1MPM(transport_handler, lcd)
