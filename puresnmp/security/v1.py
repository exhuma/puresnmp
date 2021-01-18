from puresnmp.security import SecurityModel

IDENTIFIER = 1


class SNMPv1SecurityModel(SecurityModel):
    pass


def create() -> SNMPv1SecurityModel:
    return SNMPv1SecurityModel()
