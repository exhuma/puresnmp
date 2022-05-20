"""
This module provides the SNMP security model for community based v1 exchanges
"""
from warnings import warn

from x690.types import Integer, OctetString, Sequence

from puresnmp.credentials import V1, Credentials
from puresnmp.exc import ErrorResponse, SnmpError
from puresnmp.pdu import PDU
from puresnmp.plugins.security import SecurityModel

IDENTIFIER = 1


class SNMPv1SecurityModel(SecurityModel[PDU, Sequence]):
    """
    Implementation of the SNMPv1 community based security model
    """

    def generate_request_message(
        self,
        message: PDU,
        security_engine_id: bytes,  # pylint: disable=unused-argument
        credentials: Credentials,
    ) -> Sequence:
        if not isinstance(credentials, V1):
            raise SnmpError(
                "Credentials for the SNMPv1 security model must be "
                "V1 instances!"
            )

        # The SNMPv1 support is blatantly ripping off the SNMPv2c
        # implementation which is *mostly* equivalent. Once the distinctions
        # have been ironed out, this warning can be removed.
        warn("Experimental SNMPv1 support", UserWarning)

        packet = Sequence(
            [Integer(0), OctetString(credentials.community), message]
        )
        return packet

    def process_incoming_message(
        self,
        message: Sequence,
        credentials: Credentials,
    ) -> PDU:
        proto_version, community, pdu = message
        if not isinstance(credentials, V1):
            raise SnmpError(
                "Credentials for the SNMPv1 security model must be "
                "V1 instances!"
            )

        # The SNMPv1 support is blatantly ripping off the SNMPv2c
        # implementation which is *mostly* equivalent. Once the distinctions
        # have been ironed out, this warning can be removed.
        warn("Experimental SNMPv1 support", UserWarning)

        if proto_version.pythonize() != 0:
            raise SnmpError(
                "Incoming SNMP message is not supported by the SNMPv1 "
                "security model. Most likely the device is not talking "
                f"SNMPv1 but rather a different SNMP version ({proto_version})."
            )

        if community.pythonize() != credentials.community.encode("ascii"):
            raise SnmpError("Mismatching community in response message!")

        return pdu  # type: ignore


def create() -> SNMPv1SecurityModel:
    """
    Create a new instance of the security model
    """
    return SNMPv1SecurityModel()
