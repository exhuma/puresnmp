"""
This module implements community based security model for SNMP
"""
from typing import Union

from x690.types import Integer, OctetString, Sequence

from puresnmp.adt import EncryptedMessage, PlainMessage
from puresnmp.credentials import V2C, Credentials
from puresnmp.exc import SnmpError
from puresnmp.security import SecurityModel

IDENTIFIER = 2


class SNMPv2cSecurityModel(SecurityModel):
    """
    Implementation of the security model for community based SNMPv2 messages
    """

    def generate_request_message(
        self,
        message: PlainMessage,
        security_engine_id: bytes,
        credentials: Credentials,
    ) -> Union[PlainMessage, EncryptedMessage]:
        packet = Sequence(
            [Integer(1), OctetString(credentials.community), message]
        )
        return packet

    def process_incoming_message(
        self,
        message: Union[PlainMessage, EncryptedMessage],
        credentials: Credentials,
    ) -> PlainMessage:
        proto_version, community, pdu = message
        if not isinstance(credentials, V2C):
            raise TypeError("Credentials must be V2C instances!")
        if proto_version.pythonize() != 1:
            raise SnmpError("Incorrect SNMP version on response message")
        if community.pythonize() != credentials.community.encode("ascii"):
            raise SnmpError("Incorrect community in response mesasge!")

        return pdu


def create() -> SNMPv2cSecurityModel:
    """
    Creates a new instance of the SNMPv2 community-based security model
    """
    return SNMPv2cSecurityModel()
