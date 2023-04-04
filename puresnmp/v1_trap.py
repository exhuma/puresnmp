"""
Model for a SNMPv1 Trap Message.

Specific to SNMPv1, these messages pretty much do not relate at all to the
typical PDU format otherwise used throughout SNMP - including no use of 3 of the
4 PDU base fields (request-id, error-status, error-index).

This class fulfills the otherwise missing format for TAG 4
(as is commented into pdu.py).
"""

import dataclasses
import datetime
import enum
import logging
import typing

import ipaddress
import puresnmp.exc
import puresnmp.types
import puresnmp.varbind
import x690
import x690.types
import x690.util

LOG = logging.getLogger(__name__)


class GenericTrap(enum.IntEnum):
    COLD_START = 0
    WARM_START = 1
    LINK_DOWN = 2
    LINK_UP = 3
    AUTHENTICATION_FAILURE = 4
    EGP_NEIGHBOR_LOSS = 5
    ENTERPRISE_SPECIFIC = 6


@dataclasses.dataclass(frozen=True)
class TrapV1Content:
    enterprise: x690.types.ObjectIdentifier
    agent_addr: ipaddress.IPv4Address
    generic_trap: GenericTrap
    specific_trap: int
    time_stamp: typing.Optional[datetime.timedelta]
    varbinds: typing.List[puresnmp.varbind.VarBind]


class TrapV1(x690.types.X690Type[TrapV1Content]):
    """
    Represents an SNMPv1 Trap
    - https://www.rfc-editor.org/rfc/rfc1157#page-27
    """

    TYPECLASS = x690.util.TypeClass.CONTEXT
    TAG = 4

    @property
    def value(self) -> TrapV1Content:
        if not isinstance(self.pyvalue, x690.types._SENTINEL_UNINITIALISED):
            return self.pyvalue
        self.pyvalue = self.decode_raw(self.raw_bytes, self.bounds)
        return self.pyvalue

    @staticmethod
    def decode_raw(data: bytes, slc: slice = slice(None)) -> TrapV1Content:
        if not data:
            raise puresnmp.exc.EmptyMessage("No data to decode!")
        enterprise, nxt = x690.decode(
            data, slc.start or 0, enforce_type=x690.types.ObjectIdentifier
        )
        agent_addr, nxt = x690.decode(
            data, nxt, enforce_type=puresnmp.types.IpAddress
        )
        generic_trap, nxt = x690.decode(
            data, nxt, enforce_type=x690.types.Integer
        )
        specific_trap, nxt = x690.decode(
            data, nxt, enforce_type=x690.types.Integer
        )
        time_stamp, nxt = x690.decode(
            data, nxt, enforce_type=puresnmp.types.TimeTicks
        )
        values, nxt = x690.decode(data, nxt, enforce_type=x690.types.Sequence)

        if not isinstance(values, x690.types.Sequence):
            raise TypeError(
                "Values can only be decoded from sequences but got "
                "%r instead" % type(values)
            )

        varbinds = []
        for oid, value in values:  # type: ignore
            oid = typing.cast(x690.types.ObjectIdentifier, oid)  # type: ignore
            value = typing.cast(x690.types.Type[typing.Any], value)  # type: ignore
            varbinds.append(puresnmp.varbind.VarBind(oid, value))

        return TrapV1Content(
            enterprise,
            agent_addr.value,
            GenericTrap(generic_trap.value),
            specific_trap.value,
            time_stamp.pythonize(),
            varbinds,
        )

    def __repr__(self) -> str:
        try:
            return "%s(%r, %r, %r, %r, %r, %r)" % (
                self.__class__.__name__,
                self.value.enterprise,
                self.value.agent_addr,
                self.value.generic_trap,
                self.value.specific_trap,
                self.value.time_stamp,
                self.value.varbinds,
            )
        except:  # pylint: disable=bare-except
            LOG.exception(
                "Exception caught in __repr__ of %s", self.__class__.__name__
            )
            return f"<{self.__class__.__name__} (error-in repr)>"
