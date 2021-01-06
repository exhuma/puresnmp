from enum import Enum
from typing import NamedTuple, Optional


class Auth(NamedTuple):
    key: str
    method: str


class Priv(NamedTuple):
    key: str
    method: str


class Credentials:
    pass


class V1(Credentials):
    __slots__ = ["community"]

    def __init__(self, community: str) -> None:
        self.community = community

    def __eq__(self, other: "V1") -> bool:
        return isinstance(other, V1) and other.community == self.community


class V2C(V1):
    pass


class V3(Credentials):
    __slots__ = ["auth", "priv"]

    def __init__(
        self, auth: Optional[Auth] = None, priv: Optional[Priv] = None
    ) -> None:
        self.auth = auth
        self.priv = priv

    def __eq__(self, other: "V3") -> bool:
        return (
            isinstance(other, V3)
            and other.auth == self.auth
            and other.priv == self.priv
        )
