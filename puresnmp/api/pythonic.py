"""
This module provides the high-level wrapper :py:class:`.PyWrapper` around
:py:class:`puresnmp.api.raw.Client`.

Care is taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.

This module provides "syntactic sugar" around the lower-level, but almost
identical, module :py:mod:`puresnmp.api.raw`.

While this "pythonic" API returns native Python types, the "raw" module
returns the variable types unmodified which are all subclasses of
:py:class:`x690.types.Type`.


>>> import asyncio
>>> from puresnmp import Client, V2C, PyWrapper
>>>
>>> async def example():
...    client = PyWrapper(Client("192.0.2.1", V2C("public")))
...    output = await client.get("1.3.6.1.2.1.1.1.0")
...    return output
"""

import logging
from collections import OrderedDict
from datetime import timedelta
from typing import Any, AsyncGenerator, Dict, List

from x690.types import ObjectIdentifier, Type

from ..const import ERRORS_STRICT
from ..pdu import Trap
from ..util import BulkResult, TTableRow
from ..varbind import PyVarBind
from . import raw

LOG = logging.getLogger(__name__)
TWalkResponse = AsyncGenerator[PyVarBind, None]


class PyWrapper:
    """
    A wrapper around a :py:class:`puresnmp.api.raw.Client` instance.

    The wrapper ensures conversion of internal API data-types to and from
    Python-native types.

    Using Python native types shields from internal changes internally in
    :py:mod:`puresnmp` at the cost of flexibility. Most applications should
    mostly benefit from this.

    In cases internal data-types are still wanted, one can access the
    ``.client`` attribute of PyWrapper instances which exposes the same API but
    with internally used data-types.
    """

    client: raw.Client

    def __init__(self, client: raw.Client) -> None:
        self.client = client

    async def get(self, oid: str) -> Any:
        """
        Delegates to :py:meth:`puresnmp.api.raw.Client.get` but
        converts internal types to simple Python types.
        """
        oid_internal = ObjectIdentifier(oid)
        raw_value = await self.client.get(oid_internal)
        return raw_value.pythonize()

    async def getnext(self, oid: str) -> PyVarBind:
        """
        Delegates to :py:meth:`puresnmp.api.raw.Client.getnext` but
        converts internal types to simple Python types.
        """
        varbind = await self.client.getnext(ObjectIdentifier(oid))
        return PyVarBind.from_raw(varbind)

    async def set(self, oid: str, value: Type[Any]) -> Dict[str, Any]:
        """
        Delegates to :py:meth:`puresnmp.api.raw.Client.set` but
        converts internal types to simple Python types.
        """
        result = await self.multiset({oid: value})
        return result[oid.lstrip(".")]  # type: ignore

    async def multiset(self, mappings: Dict[str, Type[Any]]) -> Dict[str, Any]:
        """
        Delegates to :py:meth:`puresnmp.api.raw.Client.multiset` but
        converts internal types to simple Python types.
        """

        mappings_internal = {
            ObjectIdentifier(oid): value for oid, value in mappings.items()
        }
        raw_output = await self.client.multiset(mappings_internal)
        pythonized = {
            str(oid): value.pythonize() for oid, value in raw_output.items()
        }
        return pythonized

    async def walk(
        self,
        oid: str,
        errors: str = ERRORS_STRICT,
    ) -> TWalkResponse:
        """
        Delegates to :py:meth:`puresnmp.api.raw.Client.walk` but
        converts internal types to simple Python types.
        """
        raw_result = self.client.walk(ObjectIdentifier(oid), errors)
        async for varbind in raw_result:
            yield PyVarBind.from_raw(varbind)

    async def multiwalk(self, oids: List[str]) -> TWalkResponse:
        """
        Delegates to :py:meth:`puresnmp.api.raw.Client.multiwalk` but
        converts internal types to simple Python types.
        """
        oids_internal = [ObjectIdentifier(oid) for oid in oids]
        async for varbind in self.client.multiwalk(oids_internal):
            yield PyVarBind.from_raw(varbind)

    async def multiget(self, oids: List[str]) -> List[Any]:
        """
        Delegates to :py:meth:`puresnmp.api.raw.Client.multiget` but
        converts internal types to simple Python types.
        """
        oids_internal = [ObjectIdentifier(oid) for oid in oids]
        raw_output = await self.client.multiget(oids_internal)
        pythonized = [value.pythonize() for value in raw_output]
        return pythonized

    async def bulkwalk(
        self,
        oids: List[str],
        bulk_size: int = 10,
    ) -> TWalkResponse:
        """
        Delegates to :py:meth:`puresnmp.api.raw.Client.bulkwalk` but
        converts internal types to simple Python types.
        """
        oids_internal = [ObjectIdentifier(oid) for oid in oids]
        result = self.client.bulkwalk(oids_internal, bulk_size=bulk_size)
        async for varbind in result:
            yield PyVarBind.from_raw(varbind)

    async def bulkget(
        self,
        scalar_oids: List[str],
        repeating_oids: List[str],
        max_list_size: int = 10,
    ) -> BulkResult:
        """
        Delegates to :py:meth:`puresnmp.api.raw.Client.bulkget` but
        converts internal types to simple Python types.
        """

        scalar_oids_int = [ObjectIdentifier(oid) for oid in scalar_oids]
        repeating_oids_int = [ObjectIdentifier(oid) for oid in repeating_oids]
        raw_output = await self.client.bulkget(
            scalar_oids_int,
            repeating_oids_int,
            max_list_size=max_list_size,
        )
        pythonized_scalars = {
            oid: value.pythonize() for oid, value in raw_output.scalars.items()
        }
        pythonized_list = OrderedDict(
            [
                (oid, value.pythonize())
                for oid, value in raw_output.listing.items()
            ]
        )
        return BulkResult(pythonized_scalars, pythonized_list)

    async def table(
        self,
        oid: str,
        _rowtype: TTableRow = Dict[str, Any],  # type: ignore
    ) -> List[Dict[str, Any]]:
        """
        Delegates to :py:meth:`puresnmp.api.raw.Client.table` but
        converts internal types to simple Python types.
        """
        tmp: List[TTableRow] = await self.client.table(
            ObjectIdentifier(oid), _rowtype=_rowtype
        )
        output = []
        for row in tmp:
            index = row.pop("0")
            pythonized = {key: value.pythonize() for key, value in row.items()}
            pythonized["0"] = index
            output.append(pythonized)
        return output

    async def bulktable(
        self,
        oid: str,
        bulk_size: int = 10,
        _rowtype: TTableRow = Dict[str, Any],  # type: ignore
    ) -> List[TTableRow]:
        """
        Delegates to :py:meth:`puresnmp.api.raw.Client.bulktable` but
        converts internal types to simple Python types.
        """
        tmp: List[TTableRow] = await self.client.bulktable(
            ObjectIdentifier(oid), bulk_size=bulk_size, _rowtype=_rowtype
        )
        output: List[TTableRow] = []
        for row in tmp:
            index = row.pop("0")
            pythonized = {key: value.pythonize() for key, value in row.items()}
            pythonized["0"] = index
            output.append(pythonized)  # type: ignore
        return output


class TrapInfo:
    """
    This class wraps a :py:class:`puresnmp.pdu.Trap` instance (accessible via
    ``raw_trap`` and makes values available as "pythonic" values.
    """

    #: The raw Trap PDU.
    #:
    #: .. warning::
    #:     This will leak data-types which are used internally by ``puresnmp``
    #:     and may change even in minor updates. You should, if possible use
    #:     the values from the properties on this object.  This exist mainly to
    #:     expose values which can be helpful in debugging.  If something is
    #:     missing from the properties, please open a corresponding support
    #:     ticket!
    raw_trap: Trap

    def __init__(self, raw_trap: Trap) -> None:
        self.raw_trap = raw_trap

    def __repr__(self):
        # type: () -> str
        return "<TrapInfo from %s on %s with %d values>" % (
            self.origin,
            self.oid,
            len(self.values),
        )

    @property
    def origin(self) -> str:
        """
        Accesses the IP-Address from which the trap was sent

        May be the empty string if the source is unknown
        """
        if self.raw_trap is None or self.raw_trap.source is None:
            return ""
        return self.raw_trap.source.address

    @property
    def uptime(self) -> timedelta:
        """
        Returns the uptime of the device.
        """
        return self.raw_trap.value.varbinds[0].value.pythonize()  # type: ignore

    @property
    def oid(self) -> str:
        """
        Returns the Trap-OID
        """
        return self.raw_trap.value.varbinds[1].value.pythonize()  # type: ignore

    @property
    def values(self):
        # type: () -> Dict[str, Any]
        """
        Returns all the values contained in this trap as dictionary mapping
        OIDs to values.
        """
        output = {}
        for varbind in self.raw_trap.value.varbinds[2:]:
            pyvarbind = PyVarBind.from_raw(varbind)
            output[pyvarbind.oid] = pyvarbind.value
        return output
