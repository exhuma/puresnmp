import sys
from dataclasses import dataclass
from textwrap import indent
from typing import Optional, Union, cast

from x690.types import Integer, OctetString, Sequence, pop_tlv

from puresnmp.pdu import PDU

if sys.stdout.isatty():
    INDENT_STRING = " \u001b[38;5;22m│\u001b[0m "
else:
    INDENT_STRING = " │ "


@dataclass(frozen=True)
class USMSecurityParameters:
    """
    This class wraps the various values for the USM
    """

    authoritative_engine_id: bytes
    authoritative_engine_boots: int
    authoritative_engine_time: int
    user_name: bytes
    auth_params: bytes
    priv_params: bytes

    @staticmethod
    def decode(data: bytes) -> "USMSecurityParameters":
        """
        Construct a USMSecurityParameters instance from pure bytes
        """
        seq, _ = pop_tlv(data, enforce_type=Sequence)
        return USMSecurityParameters.from_snmp_type(seq)

    @staticmethod
    def from_snmp_type(seq: Sequence) -> "USMSecurityParameters":
        return USMSecurityParameters(
            authoritative_engine_id=seq[0].pythonize(),
            authoritative_engine_boots=seq[1].pythonize(),
            authoritative_engine_time=seq[2].pythonize(),
            user_name=seq[3].pythonize(),
            auth_params=seq[4].pythonize(),
            priv_params=seq[5].pythonize(),
        )

    def __bytes__(self) -> bytes:
        return bytes(self.as_snmp_type())

    def as_snmp_type(self) -> Sequence:
        return Sequence(
            OctetString(self.authoritative_engine_id),
            Integer(self.authoritative_engine_boots),
            Integer(self.authoritative_engine_time),
            OctetString(self.user_name),
            OctetString(self.auth_params),
            OctetString(self.priv_params),
        )

    def pretty(self, depth: int = 0) -> str:
        """
        Return a value for CLI display
        """
        lines = ["Security Parameters"]
        lines.extend(
            [
                f"{INDENT_STRING}Engine ID   : {self.authoritative_engine_id!r}",
                f"{INDENT_STRING}Engine Boots: {self.authoritative_engine_boots}",
                f"{INDENT_STRING}Engine Time : {self.authoritative_engine_time}",
                f"{INDENT_STRING}Username    : {self.user_name!r}",
                f"{INDENT_STRING}Auth Params : {self.auth_params!r}",
                f"{INDENT_STRING}Priv Params : {self.priv_params!r}",
            ]
        )
        return indent("\n".join(lines), INDENT_STRING * depth)


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
            Integer(self.message_id),
            Integer(self.message_max_size),
            OctetString(bytes(self.flags)),
            Integer(self.security_model),
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
    data: PDU

    def __bytes__(self) -> bytes:
        return bytes(self.as_snmp_type())

    @staticmethod
    def decode(data: bytes) -> "ScopedPDU":
        sequence, _ = pop_tlv(data, Sequence, strict=True)
        output = ScopedPDU(
            context_engine_id=sequence[0],
            context_name=sequence[1],
            data=sequence[2],
        )
        return output

    def as_snmp_type(self) -> Sequence:
        return Sequence(
            self.context_engine_id,
            self.context_name,
            self.data,
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
    security_parameters: Optional[USMSecurityParameters]
    scoped_pdu: Union[bytes, ScopedPDU]

    def __bytes__(self) -> bytes:
        security_parameters = b""
        if self.security_parameters is not None:
            security_parameters = bytes(self.security_parameters.as_snmp_type())
        output = bytes(
            Sequence(
                self.version,
                self.global_data.as_snmp_type(),
                OctetString(security_parameters),
                self.scoped_pdu
                if isinstance(self.scoped_pdu, bytes)
                else self.scoped_pdu,
            )
        )
        return output

    @staticmethod
    def from_sequence(seq: Sequence) -> "Message":
        version = seq[0]
        global_data = cast(Sequence, seq[1])
        security_params_raw = cast(OctetString, seq[2]).value
        security_parameters = None
        if security_params_raw != b"":
            security_parameters = USMSecurityParameters.decode(
                security_params_raw
            )

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

        message, _ = pop_tlv(data, Sequence)
        return Message.from_sequence(message)

    def pretty(self, depth: int = 0) -> str:
        lines = []

        lines.append(f"SNMP Message (version-identifier={self.version})")
        lines.extend(self.global_data.pretty(depth + 1).splitlines())
        if self.security_parameters:
            lines.extend(
                self.security_parameters.pretty(depth + 1).splitlines()
            )
        else:
            lines.append(
                indent(
                    "Security Parameters: <none>", INDENT_STRING * (depth + 1)
                )
            )
        if isinstance(self.scoped_pdu, OctetString):
            lines.append(
                indent(f"Scoped PDU (encrypted)", INDENT_STRING * (depth + 1))
            )
            lines.extend(self.scoped_pdu.pretty(depth + 2).splitlines())
        else:
            lines.extend(self.scoped_pdu.pretty(depth + 1).splitlines())
        return indent("\n".join(lines), INDENT_STRING * depth)
