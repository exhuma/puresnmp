from typing import Any

from puresnmp.mpm import AbstractEncodingResult, MessageProcessingModel

IDENTIFIER = 2


class V2XMPM(MessageProcessingModel[AbstractEncodingResult, Any]):
    """
    Message Processing Model for SNMP v2*
    """
