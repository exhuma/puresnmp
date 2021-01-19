"""
This module implements community based security model for SNMP
"""
from puresnmp.security import SecurityModel

IDENTIFIER = 2


class SNMPv2cSecurityModel(SecurityModel):
    """
    Implementation of the security model for community based SNMPv2 messages
    """


def create() -> SNMPv2cSecurityModel:
    """
    Creates a new instance of the SNMPv2 community-based security model
    """
    return SNMPv2cSecurityModel()
