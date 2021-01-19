"""
This defines a no-op security model which can be used as fallback
"""
from puresnmp.security import SecurityModel

IDENTIFIER = 0


class NullSecurityModel(SecurityModel):
    """
    This is a placeholder class for security models which don't implement any
    logic.

    A use-case is the "ANY" security model which is used during the discovery
    phase.
    """


def create() -> NullSecurityModel:
    """
    Create a new instance of the security model
    """
    return NullSecurityModel()
