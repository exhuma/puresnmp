from puresnmp.security import SecurityModel

IDENTIFIER = 2


class SNMPv2cSecurityModel(SecurityModel):
    pass


def create() -> SNMPv2cSecurityModel:
    return SNMPv2cSecurityModel()
