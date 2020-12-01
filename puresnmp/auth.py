from typing import Type, Dict
from dataclasses import dataclass
from puresnmp.exc import SnmpError


@dataclass
class AuthResult:
    data: bytes
    auth_params: bytes


class Auth:

    IDENTIFIER: str
    __registry: Dict[str, Type["Auth"]] = {}

    def __init_subclass__(cls: Type["Auth"]) -> None:
        Auth.__registry[cls.IDENTIFIER] = cls

    @staticmethod
    def create(identifier: str) -> "Auth":
        """
        Creates a message processing model according to the given identifier.
        """
        if identifier not in Auth.__registry:
            # TODO more precise exception
            raise SnmpError(f"Unknown auth-protocol: {identifier!r}")
        return Auth.__registry[identifier]()

    def authenticate_outgoing_message(
        self, auth_key: str, data: bytes
    ) -> AuthResult:
        raise NotImplementedError("Not yet implemented")


class MD5Auth(Auth):
    IDENTIFIER = "usmHMACMD5AuthProtocol"

    def authenticate_outgoing_message(
        self, auth_key: str, data: bytes
    ) -> AuthResult:
        pass
