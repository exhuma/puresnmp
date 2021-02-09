"""
This module provides the plugin for SNMPv1 message processing
"""
from typing import Any, Awaitable, Callable, Dict

from puresnmp.plugins.mpm import AbstractEncodingResult, MessageProcessingModel

IDENTIFIER = 0


class V1MPM(MessageProcessingModel[AbstractEncodingResult, Any]):
    """
    Message Processing Model for SNMPv1
    """


def create(
    transport_handler: Callable[[bytes], Awaitable[bytes]],
    lcd: Dict[str, Any],
) -> "MessageProcessingModel[AbstractEncodingResult, Any]":
    """
    Creates a new instance for V1 message processing
    """
    return V1MPM(transport_handler, lcd)
