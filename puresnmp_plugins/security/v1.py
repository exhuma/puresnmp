"""
This module provides the SNMP security model for community based v1 exchanges
"""
from x690.types import Sequence

from puresnmp.pdu import PDU
from puresnmp.plugins.security import SecurityModel

IDENTIFIER = 1


class SNMPv1SecurityModel(SecurityModel[PDU, Sequence]):
    """
    Implementation of the SNMPv1 community based security model
    """


def create() -> SNMPv1SecurityModel:
    """
    Create a new instance of the security model
    """
    return SNMPv1SecurityModel()
