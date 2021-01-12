from puresnmp.security import SecurityModel

IDENTIFIER = 0


class NullSecurityModel(SecurityModel):
    """
    This is a placeholder class for security models which don't implement any
    logic.

    A use-case is the "ANY" security model which is used during the discovery
    phase.
    """

    pass
