"""
This module contains simple "abstract data types" which are used for both
type-hinting and to keep the code more expressive & readable.
"""
import sys
from dataclasses import dataclass
from textwrap import indent
from typing import Any, Type, TypeVar, Union, cast

from x690 import decode
from x690.types import Integer, OctetString, Sequence
from x690.types import Type as XType

from puresnmp.pdu import PDU

if sys.stdout.isatty():
    # Add some colour for TTYs
    INDENT_STRING = " \u001b[38;5;22m│\u001b[0m "
else:
    INDENT_STRING = " │ "


TMessageType = TypeVar("TMessageType", bound="Message")


@dataclass(frozen=True)
class V3Flags:
    """
    This class represents the SNMP message flags.

    At the time of this writing, this only contains the flags auth, priv and
    reportable. The remaining bytes are (as of this state) reserved by the SNMP
    standard.
    """

    #: Whether the PDU exchange requires authentication
    auth: bool = False
    #: Whether the PDU exchange requires privacy (encryption)
    priv: bool = False
    #: Whether the exchanged PDU expects a response
    reportable: bool = False

    @staticmethod
    def decode(blob: OctetString) -> "V3Flags":
        """
        Converts an OctetString instance into a more pythonic instance

        >>> V3Flags.decode(OctetString(b"\\x00"))
        V3Flags(auth=False, priv=False, reportable=False)
        >>> V3Flags.decode(OctetString(b"\\x07"))
        V3Flags(auth=True, priv=True, reportable=True)
        """
        # TODO: Other "decode" methods use "bytes" as input value -> consistency
        flags = int.from_bytes(blob.pythonize(), "big")
        reportable = bool(flags & 0b100)
        priv = bool(flags & 0b010)
        auth = bool(flags & 0b001)
        return V3Flags(auth, priv, reportable)

    def __bytes__(self) -> bytes:
        value = 0
        value |= int(self.reportable) << 2
        value |= int(self.priv) << 1
        value |= int(self.auth)
        return bytes([value])


@dataclass(frozen=True)
class HeaderData:
    """
    Header information for an SNMPv3 message
    """

    #: ID to match responses with requests
    message_id: int
    #: Maximum number of bytes accepted by the SNMP engine
    message_max_size: int
    #: Additional boolean flags about the message
    flags: V3Flags
    #: The security model required to process this message (identified by a
    #: IANA registered ID). See :py:mod:`puresnmp.security`
    security_model: int

    # TODO: explode "flags" into its components

    def as_snmp_type(self) -> Sequence:
        """
        Convert this header-data object into an x.690 Sequence
        """
        return Sequence(
            [
                Integer(self.message_id),
                Integer(self.message_max_size),
                OctetString(bytes(self.flags)),
                Integer(self.security_model),
            ]
        )

    def __bytes__(self) -> bytes:
        return bytes(self.as_snmp_type())

    def pretty(self, depth: int = 0) -> str:
        """
        Return a prettyfied string of this object.

        This prettyfied string is useful for debugging and introspection.

        :param depth: How many levels of indentation to apply. This is used
            internally for nested structures.
        """
        lines = []
        lines.append("Global Data")
        lines.append(f"{INDENT_STRING}Message ID: {self.message_id}")
        lines.append(
            f"{INDENT_STRING}Message max size: {self.message_max_size}"
        )
        lines.append(f"{INDENT_STRING}Flags: {self.flags}")
        lines.append(f"{INDENT_STRING}Security Model: {self.security_model}")
        return indent("\n".join(lines), INDENT_STRING * depth)


@dataclass(frozen=True)
class ScopedPDU:
    """
    A data-structure wrapping the different values from a SNMPv3 "Scoped PDU"
    """

    context_engine_id: OctetString
    context_name: OctetString

    #: A PDU-structure as defined in SNMPv2
    data: PDU

    def __bytes__(self) -> bytes:
        return bytes(self.as_snmp_type())

    @staticmethod
    def decode(data: bytes, slc: slice = slice(None)) -> "ScopedPDU":
        """
        Create a ScopedPDU instance from an x.690 bytes object

        :param bytes: the bytes object which contains the PDU.
        :param slc: The slice at which the object is located. If left to the
            default, it will assume that the object is located in the beginning
            of the bytes object.

        >>> from puresnmp.pdu import GetRequest, PDUContent, VarBind
        >>> from x690.types import ObjectIdentifier as OID
        >>> pdu = ScopedPDU(
        ...     OctetString(b"engine"),
        ...     OctetString(b"context"),
        ...     GetRequest(PDUContent(42, [])),
        ... )
        >>> result = ScopedPDU.decode(bytes(pdu))
        >>> pdu == result
        True
        """
        sequence, _ = decode(
            data,
            start_index=slc.start or 0,
            enforce_type=Sequence,
            strict=False,
        )
        engine_id = cast(OctetString, sequence[0])
        cname = cast(OctetString, sequence[1])
        pdu = cast(PDU, sequence[2])
        output = ScopedPDU(
            context_engine_id=engine_id,
            context_name=cname,
            data=pdu,
        )
        return output

    def as_snmp_type(self) -> Sequence:
        """
        Convert this message into an x.690 Sequence
        """
        return Sequence(
            [
                self.context_engine_id,
                self.context_name,
                self.data,
            ]
        )

    def pretty(self, depth: int = 0) -> str:
        """
        Return a prettyfied string of this object.

        This prettyfied string is useful for debugging and introspection.

        :param depth: How many levels of indentation to apply. This is used
            internally for nested structures.
        """
        ids = INDENT_STRING
        lines = []
        lines.append("Scoped PDU")
        lines.append(
            f"{ids}Context Engine ID: {self.context_engine_id.value!r}"
        )
        lines.append(f"{ids}Context Name: {self.context_name.value!r}")
        lines.extend(self.data.pretty(1).splitlines())
        return indent("\n".join(lines), INDENT_STRING * depth)


@dataclass(frozen=True)
class Message:
    """
    A complete SNMP message including all information needed by :rfc:`3411`

    Such a message contains an "old-style" PDU (as was defined in SNMPv2)
    plus some meta-data. The meta-data consists of a version identifier to
    identify the proper "message-processing-model" using a IANA registered
    value.

    .. seealso::
        `RFC definition <https://tools.ietf.org/html/rfc3412#section-6>`_
            The MIB definition of an SNMPv3 message
        `Example Message Format <http://www.tcpipguide.com/free/t_SNMPVersion3SNMPv3MessageFormat.htm>`_
            A simple visual representation of the byte-structure of an SNMPv3 message
        `IANA Message Processing Models <https://www.iana.org/assignments/snmp-number-spaces/snmp-number-spaces.xml#snmp-number-spaces-2>`_
            Oficially registered message "version" identifiers
    """

    #: The IANA version identifier
    version: Integer
    #: Additional information wrapping the old-style PDU
    header: HeaderData
    #: Additional data needed to authenticate & en/decrypt the message
    security_parameters: bytes
    #: The "old-style" PDU (either plain or encrypted)
    scoped_pdu: Union[OctetString, ScopedPDU]

    def __bytes__(self) -> bytes:
        spdu: XType[Any]
        if isinstance(self.scoped_pdu, ScopedPDU):
            spdu = self.scoped_pdu.as_snmp_type()
        else:
            spdu = self.scoped_pdu

        output = bytes(
            Sequence(
                [
                    self.version,
                    self.header.as_snmp_type(),
                    OctetString(self.security_parameters),
                    spdu,
                ]
            )
        )
        return output

    @classmethod
    def from_sequence(cls: Type[TMessageType], seq: Sequence) -> TMessageType:
        """
        Construct a Message instance from an X.690 Sequence
        """
        version = cast(Integer, seq[0])
        header = cast(Sequence, seq[1])
        security_parameters = cast(OctetString, seq[2]).value

        msg_id = cast(Integer, header[0])
        msg_max_size = cast(Integer, header[1])
        security_level = V3Flags.decode(cast(OctetString, header[2]))
        security_model_id = cast(Integer, header[3]).pythonize()

        if security_level.priv:
            payload: Union[OctetString, ScopedPDU] = cast(OctetString, seq[3])
        else:
            scoped_pdu = cast(Sequence, seq[3])
            engine_id = cast(OctetString, scoped_pdu[0])
            context_name = cast(OctetString, scoped_pdu[1])
            pdu = cast(PDU, scoped_pdu[2])
            payload = ScopedPDU(engine_id, context_name, pdu)

        output = cls(
            version,
            HeaderData(
                msg_id.pythonize(),
                msg_max_size.pythonize(),
                security_level,
                security_model_id,
            ),
            security_parameters,
            payload,
        )

        return output

    @staticmethod
    def decode(data: bytes) -> Union["PlainMessage", "EncryptedMessage"]:
        """
        Construct a new SNMPv3 message from a bytes object

        >>> from puresnmp.pdu import GetRequest, PDUContent
        >>> from x690.types import ObjectIdentifier as OID
        >>> pdu = ScopedPDU(
        ...     OctetString(b"engine"),
        ...     OctetString(b"context"),
        ...     GetRequest(PDUContent(42, [])),
        ... )
        >>> msg = PlainMessage(
        ...     version=Integer(3),
        ...     header=HeaderData(42, 65000, V3Flags(False, False, False), 3),
        ...     security_parameters=b"",
        ...     scoped_pdu=pdu
        ... )
        >>> result = Message.decode(bytes(msg))
        >>> result == msg
        True
        """

        message, _ = decode(data, enforce_type=Sequence)
        cls = (
            EncryptedMessage
            if isinstance(message[3], OctetString)
            else PlainMessage
        )
        return cls.from_sequence(message)  # type: ignore

    def pretty(self, depth: int = 0) -> str:
        """
        Return a prettyfied string of this object.

        This prettyfied string is useful for debugging and introspection.

        :param depth: How many levels of indentation to apply. This is used
            internally for nested structures.
        """
        lines = []

        lines.append(f"SNMP Message (version-identifier={self.version})")
        lines.extend(self.header.pretty(depth + 1).splitlines())
        lines.append(indent("Security Parameters", INDENT_STRING * (depth + 1)))
        lines.extend(
            OctetString(self.security_parameters).pretty(depth + 2).splitlines()
        )
        if isinstance(self.scoped_pdu, bytes):
            lines.append(
                indent("Scoped PDU (encrypted)", INDENT_STRING * (depth + 1))
            )
            lines.extend(
                OctetString(self.scoped_pdu).pretty(depth + 2).splitlines()
            )
        else:
            lines.extend(self.scoped_pdu.pretty(depth + 1).splitlines())
        return indent("\n".join(lines), INDENT_STRING * depth)


class PlainMessage(Message):
    """
    A message whose PDU is not encrypted
    """

    version: Integer
    header: HeaderData
    security_parameters: bytes
    scoped_pdu: ScopedPDU


class EncryptedMessage(Message):
    """
    A message whose PDU is encrypted
    """

    version: Integer
    header: HeaderData
    security_parameters: bytes
    scoped_pdu: OctetString
