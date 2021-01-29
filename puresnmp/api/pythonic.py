"""
This module contains the high-level functions to access the library.

Care is taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.

This module provides "syntactic sugar" around the lower-level, but almost
identical, module :py:mod:`puresnmp.api.raw`.

The "raw" module returns the variable types unmodified which are all subclasses
of :py:class:`x690.types.Type`.
"""

import logging
from collections import OrderedDict
from datetime import timedelta
from typing import Any, AsyncGenerator, Dict, List
from warnings import warn

from x690.types import ObjectIdentifier

from ..const import DEFAULT_TIMEOUT, ERRORS_STRICT
from ..pdu import Trap
from ..util import BulkResult
from ..varbind import PyVarBind
from . import raw

LOG = logging.getLogger(__name__)
OID = ObjectIdentifier
TWalkResponse = AsyncGenerator[PyVarBind, None]


class PyWrapper:
    """
    A wrapper around a :py:class:`puresnmp.api.raw.Client` instance.

    The wrapper ensures converstion of internal API data-type to and from
    Python-native types.

    Using Python native types shields from internal changes internally in
    :py:mod:`puresnmp` at the cost of loss of flexibility. Most applications
    should mostly benefit from this.

    In cases internal data-types are still wanted, one can access the
    ``.client`` attribute of PyWrapper instances which exposes the same API but
    with internally used data-types.
    """

    def __init__(self, client: raw.Client) -> None:
        self.client = client

    async def get(self, *args, **kwargs) -> None:
        """
        Delegates to :py:meth:`~puresnmp.api.raw.Client.get` but returns
        a simple Python type.

        See the "raw" equivalent for detailed documentation & examples.
        """
        raw_value = await self.client.get(*args, **kwargs)
        return raw_value.pythonize()

    async def getnext(
        self, oid: str, timeout: int = DEFAULT_TIMEOUT
    ) -> PyVarBind:
        """
        Delegates to :py:meth:`~puresnmp.api.raw.Client.getnext` but returns
        simple Python types.

        See the "raw" equivalent for detailed documentation & examples.
        """
        varbind = await self.client.getnext(
            ObjectIdentifier(oid), timeout=timeout
        )
        return PyVarBind.from_raw(varbind)

    async def set(self, oid, value, timeout: int = 6) -> Dict[str, Any]:
        """
        Delegates to :py:meth:`~puresnmp.api.raw.Client.set` but returns
        simple Python types.

        See the "raw" equivalent for detailed documentation & examples.
        """

        result = await self.multiset({oid: value}, timeout)
        return result[oid.lstrip(".")]  # type: ignore

    async def multiset(self, mappings, timeout: int = 6):
        """
        Delegates to :py:func:`~puresnmp.api.raw.Client.multiset` but
        returns simple Python types.

        See the "raw" equivalent for detailed documentation & examples.
        """

        raw_output = await self.client.multiset(mappings, timeout=timeout)
        pythonized = {
            str(oid): value.pythonize() for oid, value in raw_output.items()
        }
        return pythonized

    async def walk(
        self,
        oid: str,
        timeout: int = DEFAULT_TIMEOUT,
        errors: str = ERRORS_STRICT,
    ) -> TWalkResponse:
        """
        Delegates to :py:meth:`~puresnmp.api.raw.Client.walk` but returns
        simple Python types.

        See the "raw" equivalent for detailed documentation & examples.
        """

        raw_result = self.client.walk(ObjectIdentifier(oid), timeout, errors)
        async for varbind in raw_result:
            yield PyVarBind.from_raw(varbind)

    async def multiwalk(
        self,
        oids: List[str],
        timeout: int = DEFAULT_TIMEOUT,
    ) -> TWalkResponse:
        """
        Delegates to :py:meth:`~puresnmp.api.raw.Client.multiwalk` but
        returns simple Python types.

        See the "raw" equivalent for detailed documentation & examples.
        """
        oids_internal = [ObjectIdentifier(oid) for oid in oids]
        async for varbind in self.client.multiwalk(
            oids_internal, timeout=timeout
        ):
            yield PyVarBind.from_raw(varbind)

    async def multiget(
        self, oids: List[str], timeout: int = DEFAULT_TIMEOUT
    ) -> List[Any]:
        """
        Delegates to :py:meth:`~puresnmp.api.raw.Client.multiget` but
        returns simple Python types.

        See the "raw" equivalent for detailed documentation & examples.
        """
        oids_internal = [ObjectIdentifier(oid) for oid in oids]
        raw_output = await self.client.multiget(oids_internal, timeout)
        pythonized = [value.pythonize() for value in raw_output]
        return pythonized

    async def bulkwalk(
        self,
        oids: List[str],
        bulk_size: int = 10,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> TWalkResponse:
        """
        Delegates to :py:meth:`~puresnmp.api.raw.Client.bulkwalk` but returns
        simple Python types.

        See the "raw" equivalent for detailed documentation & examples.
        """

        oids_internal = [ObjectIdentifier(oid) for oid in oids]
        result = self.client.bulkwalk(
            oids_internal,
            bulk_size=bulk_size,
            timeout=timeout,
        )
        async for varbind in result:
            yield PyVarBind.from_raw(varbind)

    async def bulkget(
        self,
        scalar_oids: List[str],
        repeating_oids: List[str],
        max_list_size: int = 1,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> BulkResult:
        """
        Delegates to :py:meth:`~puresnmp.api.raw.Client.bulkget` but
        returns simple Python types.

        See the "raw" equivalent for detailed documentation & examples.
        """

        scalar_oids_int = [ObjectIdentifier(oid) for oid in scalar_oids]
        repeating_oids_int = [ObjectIdentifier(oid) for oid in repeating_oids]
        raw_output = await self.client.bulkget(
            scalar_oids_int,
            repeating_oids_int,
            max_list_size=max_list_size,
            timeout=timeout,
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
        self, oid: str, num_base_nodes: int = 0, timeout: int = DEFAULT_TIMEOUT
    ) -> List[Dict[str, Any]]:
        """
        Fetches a table from the SNMP agent. Each value will be converted to a
        pure-python type.

        See :py:func:`puresnmp.api.raw.table` for more information of the
        returned structure.
        """
        if num_base_nodes:
            warn(
                'Usage of "num_base_nodes" in table operations is no longer '
                "required",
                DeprecationWarning,
                stacklevel=2,
            )
        tmp = await self.client.table(
            ObjectIdentifier(oid),
            num_base_nodes=num_base_nodes,
            timeout=timeout,
        )
        output = []
        for row in tmp:
            index = row.pop("0")
            pythonized = {key: value.pythonize() for key, value in row.items()}
            pythonized["0"] = index
            output.append(pythonized)
        return output

    async def bulktable(
        self, oid: str, num_base_nodes: int = 0, bulk_size: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Fetch an SNMP table using "bulk" requests converting the values into
        pure Python types.

        See :py:func:`puresnmp.api.raw.Client.table` for more
        information of the returned structure.

        .. versionadded: 1.7.0
        """
        if num_base_nodes:
            warn(
                'Usage of "num_base_nodes" in table operations is no longer '
                "required",
                DeprecationWarning,
                stacklevel=2,
            )
        tmp = await self.client.bulktable(
            ObjectIdentifier(oid),
            num_base_nodes=num_base_nodes,
            bulk_size=bulk_size,
        )
        output = []
        for row in tmp:
            index = row.pop("0")
            pythonized = {key: value.pythonize() for key, value in row.items()}
            pythonized["0"] = index
            output.append(pythonized)
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
