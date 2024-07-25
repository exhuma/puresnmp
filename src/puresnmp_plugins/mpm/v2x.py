from typing import Any, Awaitable, Callable, Dict

from puresnmp.plugins.mpm import AbstractEncodingResult, MessageProcessingModel

IDENTIFIER = 2


class V2XMPM(MessageProcessingModel[AbstractEncodingResult, Any]):
    """
    Message Processing Model for SNMP v2*
    """


def create(
    transport_handler: Callable[[bytes], Awaitable[bytes]],
    lcd: Dict[str, Any],
) -> "MessageProcessingModel[AbstractEncodingResult, Any]":
    """
    Creates a new instance for V1 message processing
    """
    return V2XMPM(transport_handler, lcd)
