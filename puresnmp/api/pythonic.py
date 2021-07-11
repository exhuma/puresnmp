"""
This module contains the high-level functions to access the library.

Care is taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.

This module provides "syntactic sugar" around the lower-level, but almost
identical, module :py:mod:`puresnmp.api.raw`.

The "raw" module returns the variable types unmodified which are all subclasses
of :py:class:`puresnmp.x690.types.Type`.
"""

# TODO (advanced): This module should not make use of it's own functions. The
#     is beginning to be too "thick", containing too much business logic for a
#     mere abstraction layer.
#     module exists as an abstraction layer only. If one function uses a
#     "siblng" function, valuable information is lost. In general, this module


from __future__ import unicode_literals

import logging
from collections import OrderedDict
from datetime import timedelta
from typing import TYPE_CHECKING, TypeVar
from warnings import warn

from ..const import DEFAULT_TIMEOUT, Version
from ..pdu import Trap, VarBind
from ..util import BulkResult
from ..x690.types import ObjectIdentifier, Type
from . import raw

if TYPE_CHECKING:  # pragma: no cover
    # pylint: disable=unused-import, invalid-name
    from typing import Any, Callable, Dict, Generator, List, Tuple, Union
    from puresnmp.typevars import PyType
    TWalkResponse = Generator[VarBind, None, None]
    TFetcher = Callable[[str, str, List[str], int, int],
                        List[VarBind]]
    T = TypeVar('T', bound=PyType)

try:
    unicode = unicode  # type: Callable[[Any], str]
except NameError:
    # pylint: disable=invalid-name
    unicode = str  # type: Callable[[Any], str]

_set = set
LOG = logging.getLogger(__name__)
OID = ObjectIdentifier.from_string


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
    raw_trap = None

    def __init__(self, raw_trap):
        # type: (Trap) -> None
        self.raw_trap = raw_trap

    def __repr__(self):
        # type: () -> str
        return "<TrapInfo from %s on %s with %d values>" % (
            self.origin,
            self.oid,
            len(self.values),
        )

    @property
    def origin(self):
        # type: () -> str
        """
        Accesses the IP-Address from which the trap was sent

        May be the empty string if the source is unknown
        """
        if self.raw_trap is None or self.raw_trap.source is None:
            return ''
        return self.raw_trap.source.address

    @property
    def uptime(self):
        # type: () -> timedelta
        """
        Returns the uptime of the device.
        """
        return self.raw_trap.varbinds[0].value.pythonize()  # type: ignore

    @property
    def oid(self):
        # type: () -> str
        """
        Returns the Trap-OID
        """
        return self.raw_trap.varbinds[1].value.pythonize()  # type: ignore

    @property
    def values(self):
        # type: () -> Dict[str, Any]
        """
        Returns all the values contained in this trap as dictionary mapping
        OIDs to values.
        """
        output = {}
        for oid_raw, value_raw in self.raw_trap.varbinds[2:]:  # type: ignore
            oid = oid_raw.pythonize()  # type: ignore
            value = value_raw.pythonize()  # type: ignore
            output[oid] = value
        return output


def get(ip, community, oid, port=161, timeout=2, version=Version.V2C):
    # type: (str, str, str, int, int) -> PyType
    """
    Delegates to :py:func:`~puresnmp.api.raw.get` but returns simple Python
    types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    raw_value = raw.get(ip, community, oid, port, timeout=timeout, version=version)
    return raw_value.pythonize()  # type: ignore


def multiget(ip, community, oids, port=161, timeout=DEFAULT_TIMEOUT, version=Version.V2C):
    # type: (str, str, List[str], int, int, int) -> List[PyType]
    """
    Delegates to :py:func:`~puresnmp.api.raw.multiget` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    raw_output = raw.multiget(ip, community, oids, port, timeout, version=version)
    pythonized = [value.pythonize() for value in raw_output]
    return pythonized


def getnext(ip, community, oid, port=161, timeout=DEFAULT_TIMEOUT, version=Version.V2C):
    # type: (str, str, str, int, int) -> VarBind
    """
    Delegates to :py:func:`~puresnmp.api.raw.getnext` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    result = multigetnext(ip, community, [oid], port, timeout=timeout, version=version)
    return result[0]


def multigetnext(ip, community, oids, port=161, timeout=DEFAULT_TIMEOUT, version=Version.V2C):
    # type: (str, str, List[str], int, int, int) -> List[VarBind]
    """
    Delegates to :py:func:`~puresnmp.api.raw.multigetnext` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    raw_output = raw.multigetnext(ip, community, oids, port, timeout, version=version)
    pythonized = [VarBind(oid, value.pythonize())  # type: ignore
                  for oid, value in raw_output]
    return pythonized


def walk(ip, community, oid, port=161, timeout=DEFAULT_TIMEOUT, version=Version.V2C):
    # type: (str, str, str, int, int) -> TWalkResponse
    """
    Delegates to :py:func:`~puresnmp.api.raw.walk` but returns simple Python
    types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    raw_result = raw.walk(ip, community, oid, port, timeout, version=version)
    for raw_oid, raw_value in raw_result:
        yield VarBind(raw_oid, raw_value.pythonize())  # type: ignore


def multiwalk(ip, community, oids, port=161, timeout=DEFAULT_TIMEOUT,
              fetcher=multigetnext, version=Version.V2C):
    # type: (str, str, List[str], int, int, TFetcher, int) -> TWalkResponse
    """
    Delegates to :py:func:`~puresnmp.api.raw.multiwalk` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    raw_output = raw.multiwalk(ip, community, oids, port, timeout, fetcher,
                               version=version)
    for oid, value in raw_output:
        if isinstance(value, Type):
            value = value.pythonize()
        yield VarBind(oid, value)  # type: ignore


def set(ip, community, oid, value, port=161, timeout=DEFAULT_TIMEOUT,
        version=Version.V2C):  # pylint: disable=redefined-builtin
    # type: (str, str, str, Type[T], int, int) -> T
    """
    Delegates to :py:func:`~puresnmp.api.raw.set` but returns simple Python
    types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    result = multiset(ip, community, [(oid, value)],  # type: ignore
                      port, timeout=timeout, version=version)
    return result[oid.lstrip('.')]  # type: ignore


def multiset(ip, community, mappings, port=161, timeout=DEFAULT_TIMEOUT,
             version=Version.V2C):
    # type: (str, str, List[Tuple[str, raw.T]], int, int) -> Dict[str, PyType]
    """
    Delegates to :py:func:`~puresnmp.api.raw.multiset` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    raw_output = raw.multiset(ip, community, mappings, port, timeout,
                              version=version)
    pythonized = {unicode(oid): value.pythonize()
                  for oid, value in raw_output.items()}
    return pythonized


def bulkget(ip, community, scalar_oids, repeating_oids, max_list_size=1,
            port=161, timeout=DEFAULT_TIMEOUT, version=Version.V2C):
    # type: (str, str, List[str], List[str], int, int, int, int) -> BulkResult
    """
    Delegates to :py:func:`~puresnmp.api.raw.mulkget` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    raw_output = raw.bulkget(ip, community, scalar_oids, repeating_oids,
                             max_list_size=max_list_size,
                             port=port,
                             timeout=timeout,
                             version=version)
    pythonized_scalars = {oid: value.pythonize()
                          for oid, value in raw_output.scalars.items()}
    pythonized_list = OrderedDict(
        [(oid, value.pythonize())
         for oid, value in raw_output.listing.items()])
    return BulkResult(pythonized_scalars, pythonized_list)


def bulkwalk(ip, community, oids, bulk_size=10, port=161,
             timeout=DEFAULT_TIMEOUT, version=Version.V2C):
    # type: (str, str, List[str], int, int, int) -> TWalkResponse
    """
    Delegates to :py:func:`~puresnmp.api.raw.bulkwalk` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    result = multiwalk(
        ip, community, oids, port=port,
        fetcher=raw._bulkwalk_fetcher(  # pylint: disable=protected-access
            bulk_size),
        timeout=timeout, version=version)
    for oid, value in result:
        yield VarBind(oid, value)  # type: ignore


def table(ip, community, oid, port=161, num_base_nodes=0, version=Version.V2C):
    # type: (str, str, str, int, int) -> List[Dict[str, Any]]
    """
    Fetches a table from the SNMP agent. Each value will be converted to a
    pure-python type.

    See :py:func:`puresnmp.api.raw.table` for more information of the returned
    structure.
    """
    if num_base_nodes:
        warn(
            'Usage of "num_base_nodes" in table operations is no longer '
            "required",
            DeprecationWarning,
            stacklevel=2,
        )
    else:
        parsed_oid = OID(oid)
        num_base_nodes = len(parsed_oid) + 1  # type: ignore
    tmp = raw.table(ip, community, oid, port=port, num_base_nodes=num_base_nodes, version=version)
    output = []
    for row in tmp:
        index = row.pop('0')
        pythonized = {key: value.pythonize() for key, value in row.items()}
        pythonized['0'] = index
        output.append(pythonized)
    return output


def bulktable(ip, community, oid, port=161, num_base_nodes=0, bulk_size=10):
    # type: (str, str, str, int, int, int) -> List[Dict[str, Any]]
    """
    Fetch an SNMP table using "bulk" requests converting the values into pure
    Python types.

    See :py:func:`puresnmp.api.raw.table` for more information of the returned
    structure.

    .. versionadded: 1.7.0
    """
    if num_base_nodes:
        warn('Usage of "num_base_nodes" in table operations is no longer '
             'required', DeprecationWarning)
    else:
        parsed_oid = OID(oid)
        num_base_nodes = len(parsed_oid) + 1  # type: ignore
    tmp = raw.bulktable(ip, community, oid, port=port, bulk_size=bulk_size)
    output = []
    for row in tmp:
        index = row.pop('0')
        pythonized = {key: value.pythonize() for key, value in row.items()}
        pythonized['0'] = index
        output.append(pythonized)
    return output


def traps(listen_address='0.0.0.0', port=162, buffer_size=1024):
    # type: (str, int, int) -> Generator[TrapInfo, None, None]
    """
    A "pythonic" wrapper around :py:func:`puresnmp.api.raw.traps` output.
    """
    for raw_trap in raw.traps(listen_address, port, buffer_size):
        yield TrapInfo(raw_trap)
