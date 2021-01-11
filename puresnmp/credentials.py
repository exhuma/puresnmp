from enum import Enum
from typing import NamedTuple, Optional


class Auth(NamedTuple):
    key: bytes
    method: str


class Priv(NamedTuple):
    key: bytes
    method: str


class Credentials:

    __slots__ = ["mpm"]

    def __init__(self, mpm: int) -> None:
        self.mpm = mpm


class V1(Credentials):
    __slots__ = ["community"]

    def __init__(self, community: str) -> None:
        super().__init__(0)
        self.community = community

    def __eq__(self, other: "V1") -> bool:
        return isinstance(other, V1) and other.community == self.community


class V2C(V1):
    def __init__(self, community: str) -> None:
        super().__init__(community)
        self.mpm = 1


class V3(Credentials):
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

    def __eq__(self, other: "V3") -> bool:
        return (
            isinstance(other, V3)
            and other.username == self.username
            and other.auth == self.auth
            and other.priv == self.priv
        )
