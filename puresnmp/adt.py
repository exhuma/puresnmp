import sys
from dataclasses import dataclass
from textwrap import indent
from typing import TYPE_CHECKING, Union, cast

from x690 import decode
from x690.types import Integer, OctetString, Sequence

if TYPE_CHECKING:
    from puresnmp.pdu import PDU

if sys.stdout.isatty():
    INDENT_STRING = " \u001b[38;5;22m│\u001b[0m "
else:
    INDENT_STRING = " │ "


@dataclass(frozen=True)
class V3Flags:
    """
    This class represents the SNMP message flags.

    At the time of this writing, this only contains the flags auth, priv and
    reportable. The remaining bytes are (as of this state) reserved by the SNMP
    standard.
    """

    auth: bool = False
    priv: bool = False
    reportable: bool = False

    @staticmethod
    def decode(blob: OctetString) -> "V3Flags":
        """
        Converts an OctetString instance into a more pythonic instance
        """
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
    message_id: int
    message_max_size: int
    flags: V3Flags
    security_model: int

    def as_snmp_type(self) -> Sequence:
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
    context_engine_id: OctetString
    context_name: OctetString
    data: "PDU"

    def __bytes__(self) -> bytes:
        return bytes(self.as_snmp_type())

    @staticmethod
    def decode(data: bytes, slc: slice = slice(None)) -> "ScopedPDU":
        sequence, _ = decode(data, enforce_type=Sequence, strict=False)
        output = ScopedPDU(
            context_engine_id=sequence[0],
            context_name=sequence[1],
            data=sequence[2],
        )
        return output

    def as_snmp_type(self) -> Sequence:
        return Sequence(
            [
                self.context_engine_id,
                self.context_name,
                self.data,
            ]
        )

    def pretty(self, depth: int = 0) -> str:
        lines = []
        lines.append("Scoped PDU")
        lines.append(
            f"{INDENT_STRING}Context Engine ID: {self.context_engine_id.value!r}"
        )
        lines.append(
            f"{INDENT_STRING}Context Name: {self.context_name.value!r}"
        )
        lines.extend(self.data.pretty(1).splitlines())
        return indent("\n".join(lines), INDENT_STRING * depth)


@dataclass(frozen=True)
class Message:
    """
    A message represents the complete binary packet sent to/from the network.

    Aside from the PDU it also contains additional meta-data for message
    processing.

    See http://www.tcpipguide.com/free/t_SNMPVersion3SNMPv3MessageFormat.htm
        https://tools.ietf.org/html/rfc3412#section-6
    """

    version: Integer
    global_data: HeaderData
    security_parameters: bytes
    scoped_pdu: Union[bytes, ScopedPDU]

    def __bytes__(self) -> bytes:
        output = bytes(
            Sequence(
                [
                    self.version,
                    self.global_data.as_snmp_type(),
                    OctetString(self.security_parameters),
                    self.scoped_pdu
                    if isinstance(self.scoped_pdu, bytes)
                    else self.scoped_pdu,
                ]
            )
        )
        return output

    @staticmethod
    def from_sequence(seq: Sequence) -> "Message":
        version = seq[0]
        global_data = cast(Sequence, seq[1])
        security_parameters = cast(OctetString, seq[2]).value

        msg_id = cast(Integer, global_data[0])
        msg_max_size = cast(Integer, global_data[1])
        security_level = V3Flags.decode(cast(OctetString, global_data[2]))
        security_model_id = cast(Integer, global_data[3]).pythonize()

        if security_level.priv:
            payload: Union[OctetString, ScopedPDU] = cast(OctetString, seq[3])
        else:
            scoped_pdu = cast(Sequence, seq[3])
            payload = ScopedPDU(scoped_pdu[0], scoped_pdu[1], scoped_pdu[2])

        output = Message(
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
    def decode(data: bytes) -> "Message":
        """
        Construct a new SNMPv3 message from a bytes object
        """

        message, _ = decode(data, enforce_type=Sequence)
        return Message.from_sequence(message)

    def pretty(self, depth: int = 0) -> str:
        lines = []

        lines.append(f"SNMP Message (version-identifier={self.version})")
        lines.extend(self.global_data.pretty(depth + 1).splitlines())
        lines.append(
            indent(f"Security Parameters", INDENT_STRING * (depth + 1))
        )
        lines.extend(
            OctetString(self.security_parameters).pretty(depth + 2).splitlines()
        )
        if isinstance(self.scoped_pdu, bytes):
            lines.append(
                indent(f"Scoped PDU (encrypted)", INDENT_STRING * (depth + 1))
            )
            lines.extend(
                OctetString(self.scoped_pdu).pretty(depth + 2).splitlines()
            )
        else:
            lines.extend(self.scoped_pdu.pretty(depth + 1).splitlines())
        return indent("\n".join(lines), INDENT_STRING * depth)
