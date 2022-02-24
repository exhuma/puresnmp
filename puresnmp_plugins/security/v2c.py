"""
This module implements community based security model for SNMP
"""
from x690.types import Integer, OctetString, Sequence

from puresnmp.credentials import V2C, Credentials
from puresnmp.exc import SnmpError
from puresnmp.pdu import PDU
from puresnmp.plugins.security import SecurityModel

IDENTIFIER = 2


class SNMPv2cSecurityModel(SecurityModel[PDU, Sequence]):
    """
    Implementation of the security model for community based SNMPv2 messages
    """

    def generate_request_message(
        self,
        message: PDU,
        security_engine_id: bytes,
        credentials: Credentials,
    ) -> Sequence:
        if not isinstance(credentials, V2C):
            raise SnmpError(
                "Credentials for the SNMPv2c security model must be "
                "V2C instances!"
            )
        packet = Sequence(
            [Integer(1), OctetString(credentials.community), message]
        )
        return packet

    def process_incoming_message(
        self,
        message: Sequence,
        credentials: Credentials,
    ) -> PDU:
        proto_version, community, pdu = message
        if not isinstance(credentials, V2C):
            raise SnmpError(
                "Credentials for the SNMPv2c security model must be "
                "V2C instances!"
            )
        if proto_version.pythonize() != 1:
            raise SnmpError(
                "Incoming SNMP message is not supported by the SNMPv2c "
                "security model. Most likely the device is not talking "
                "SNMPv2c but rather a different SNMP version."
            )
        if community.pythonize() != credentials.community.encode("ascii"):
            raise SnmpError("Mismatching community in response mesasge!")

        return pdu  # type: ignore


def create() -> SNMPv2cSecurityModel:
    """
    Creates a new instance of the SNMPv2 community-based security model
    """
    return SNMPv2cSecurityModel()
