import pyDes

from puresnmp.adt import Message


class Priv:

    IDENTIFIER: str
    __registry: Dict[str, Type["Priv"]] = {}

    def __init_subclass__(cls: Type["Priv"]) -> None:
        if not hasattr(cls, "IDENTIFIER"):
            return
        Priv.__registry[cls.IDENTIFIER] = cls

    @staticmethod
    def create(identifier: str) -> "Priv":
        """
        Creates a message processing model according to the given identifier.
        """
        if identifier not in Priv.__registry:
            # TODO more precise exception
            raise SnmpError(f"Unknown auth-protocol: {identifier!r}")
        return Priv.__registry[identifier]()

    def encrypt_data(self, key: bytes, message: Message) -> Message:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        raise NotImplementedError("Not yet implemented")

    def decrypt_data(
        self, decrypt_key: bytes, priv_params: bytes, message: Message
    ) -> Message:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        raise NotImplementedError("Not yet implemented")


class DES(Priv):
    def encrypt_data(self, key: bytes, message: Message) -> Message:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """

        des = pyDes.des(key)
        encrypted = des.encrypt(message.scoped_pdu)
        message.scoped_pdu = encrypted
        print(encrypted.pretty())
        1 / 0
        return message

    def decrypt_data(
        self, decrypt_key: bytes, priv_params: bytes, message: Message
    ) -> Message:
        """
        See https://tools.ietf.org/html/rfc3414#section-1.6
        """
        1 / 0
        return message
