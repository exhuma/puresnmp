"""
This module contains helper-classes for the different credentials used in SNMP.

These credentials also define the underlying message-processing model by
their very nature. V1 credentials will use the V1 message processing model,
V2C uses the community-based V2 message-processing model and so on.
"""
from typing import NamedTuple, Optional


class Auth(NamedTuple):
    """
    Configuration for "authentication" values in SNMPv3
    """

    #: The authentication key (password)
    key: bytes
    #: The authentication method (md5, sha, ...)
    method: str


class Priv(NamedTuple):
    """
    Configuration for "privacy/encryption" values in SNMPv3
    """

    #: The privacy key (password)
    key: bytes
    #: The privacy method (des, aes, ...)
    method: str


class Credentials:
    """
    Parent class for SNMP credentials. This should not be used other than
    type-hinting. Use the concrete classes for SNMP calls.
    """

    __slots__ = ["mpm"]

    def __init__(self, mpm: int) -> None:
        self.mpm = mpm


class V1(Credentials):
    """
    Credentials for SNMPv1 exchanges

    :param community: The community-string
    """

    __slots__ = ["community"]

    def __init__(self, community: str) -> None:
        super().__init__(0)
        self.community = community

    def __eq__(self, other: object) -> bool:
        return isinstance(other, V1) and other.community == self.community


class V2C(V1):
    """
    Credentials for community-based SNMPv2 exchanges

    :param community: The community-string
    """

    def __init__(self, community: str) -> None:
        super().__init__(community)
        self.mpm = 1


class V3(Credentials):
    """
    Credentials for SNMPv3 exchanges

    :param username: The local username for SNMP exchanges
    :param auth: Authentication details. If left at "None", authentication is disabled.
    :param priv: Encryption details. If left at "None", encryption is
        disabled. Note that for encryption to be enabled, authentication must
        also be enabled.
    """

    __slots__ = ["username", "auth", "priv"]

    def __init__(
        self,
        username: str,
        auth: Optional[Auth] = None,
        priv: Optional[Priv] = None,
    ) -> None:
        super().__init__(3)
        self.username = username
        self.auth = auth
        self.priv = priv

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, V3)
            and other.username == self.username
            and other.auth == self.auth
            and other.priv == self.priv
        )
