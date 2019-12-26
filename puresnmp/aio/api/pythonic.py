"""
This module contains the high-level functions to access the library with
asyncio.

Care is taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.

This module provides "syntactic sugar" around the lower-level, but almost
identical, module :py:mod:`puresnmp.aio.api.raw`.

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
from typing import TYPE_CHECKING
from warnings import warn

from . import raw
from ...const import DEFAULT_TIMEOUT
from ...pdu import VarBind
from ...util import BulkResult
from ...x690.types import Type, ObjectIdentifier

if TYPE_CHECKING:  # pragma: no cover
    # pylint: disable=unused-import, invalid-name
    from typing import (
        Any,
        AsyncGenerator,
        Callable,
        Coroutine,
        Dict,
        List,
        Tuple,
        TypeVar,
        Union,
    )
    from puresnmp.typevars import PyType, TWrappedPyType

    TWalkResponse = AsyncGenerator[VarBind, None]
    TFetcher = Callable[[str, str, List[str], int, int],
                        Coroutine[Any, Any, List[VarBind]]]
    T = TypeVar('T', bound=PyType)  # pylint: disable=invalid-name

try:
    unicode = unicode  # type: Callable[[Any], str]
except NameError:
    # pylint: disable=invalid-name
    unicode = str  # type: Callable[[Any], str]

_set = set
LOG = logging.getLogger(__name__)
OID = ObjectIdentifier.from_string

async def get(ip, community, oid, port=161, timeout=DEFAULT_TIMEOUT):
    # type: (str, str, str, int, int) -> PyType
    """
    Delegates to :py:func:`~puresnmp.aio.api.raw.get` but returns simple Python
    types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    raw_value = await raw.get(ip, community, oid, port, timeout=timeout)
    return raw_value.pythonize()  # type: ignore


async def multiget(ip, community, oids, port=161, timeout=DEFAULT_TIMEOUT):
    # type: (str, str, List[str], int, int) -> List[PyType]
    """
    Delegates to :py:func:`~puresnmp.aio.api.raw.multiget` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    raw_output = await raw.multiget(ip, community, oids, port, timeout)
    pythonized = [value.pythonize() for value in raw_output]
    return pythonized


async def getnext(ip, community, oid, port=161, timeout=DEFAULT_TIMEOUT):
    # type: (str, str, str, int, int) -> VarBind
    """
    Delegates to :py:func:`~puresnmp.aio.api.raw.getnext` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    result = await multigetnext(ip, community, [oid], port, timeout=timeout)
    return result[0]


async def multigetnext(ip, community, oids, port=161, timeout=DEFAULT_TIMEOUT):
    # type: (str, str, List[str], int, int) -> List[VarBind]
    """
    Delegates to :py:func:`~puresnmp.aio.api.raw.multigetnext` but returns
    simple Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    raw_output = await raw.multigetnext(ip, community, oids, port, timeout)
    pythonized = [VarBind(oid, value.pythonize())  # type: ignore
                  for oid, value in raw_output]
    return pythonized


async def walk(ip, community, oid, port=161, timeout=DEFAULT_TIMEOUT):
    # type: (str, str, str, int, int) -> TWalkResponse
    """
    Delegates to :py:func:`~puresnmp.aio.api.raw.walk` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    raw_result = raw.walk(ip, community, oid, port, timeout)
    async for raw_oid, raw_value in raw_result:
        yield VarBind(raw_oid, raw_value.pythonize())  # type: ignore


async def multiwalk(ip, community, oids, port=161, timeout=DEFAULT_TIMEOUT,
                    fetcher=multigetnext):
    # type: (str, str, List[str], int, int, TFetcher) -> TWalkResponse
    """
    Delegates to :py:func:`~puresnmp.aio.api.raw.multiwalk` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    raw_output = raw.multiwalk(ip, community, oids, port, timeout, fetcher)
    async for oid, value in raw_output:
        if isinstance(value, Type):
            value = value.pythonize()
        yield VarBind(oid, value)  # type: ignore


async def set(ip, community, oid, value, port=161, timeout=DEFAULT_TIMEOUT):  # pylint: disable=redefined-builtin
    # type: (str, str, str, Type[T], int, int) -> T
    """
    Delegates to :py:func:`~puresnmp.aio.api.raw.set` but returns simple Python
    types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    result = await multiset(ip, community, [(oid, value)],
                            port, timeout=timeout)
    return result[oid.lstrip('.')]  # type: ignore


async def multiset(ip, community, mappings, port=161, timeout=DEFAULT_TIMEOUT):
    # type: (str, str, List[Tuple[str, Type[TWrappedPyType]]], int, int) -> Dict[str, TWrappedPyType]
    """
    Delegates to :py:func:`~puresnmp.aio.api.raw.multiset` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    raw_output = await raw.multiset(ip, community, mappings, port, timeout)
    pythonized = {unicode(oid): value.pythonize()
                  for oid, value in raw_output.items()}
    return pythonized


async def bulkget(ip, community, scalar_oids, repeating_oids, max_list_size=1,
                  port=161, timeout=DEFAULT_TIMEOUT):
    # type: (str, str, List[str], List[str], int, int, int) -> BulkResult
    """
    Delegates to :py:func:`~puresnmp.aio.api.raw.bulkget` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    raw_output = await raw.bulkget(ip, community, scalar_oids, repeating_oids,
                                   max_list_size=max_list_size,
                                   port=port,
                                   timeout=timeout)
    pythonized_scalars = {oid: value.pythonize()
                          for oid, value in raw_output.scalars.items()}
    pythonized_list = OrderedDict(
        [(oid, value.pythonize())
         for oid, value in raw_output.listing.items()])
    return BulkResult(pythonized_scalars, pythonized_list)


async def bulkwalk(ip, community, oids, bulk_size=10, port=161,
                   timeout=DEFAULT_TIMEOUT):
    # type: (str, str, List[str], int, int, int) -> TWalkResponse
    """
    Delegates to :py:func:`~puresnmp.aio.api.raw.bulkwalk` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    result = multiwalk(
        ip, community, oids, port=port,
        fetcher=raw._bulkwalk_fetcher(  # pylint: disable=protected-access
            bulk_size),
        timeout=timeout)
    async for oid, value in result:
        yield VarBind(oid, value)  # type: ignore


async def table(ip, community, oid, port=161, num_base_nodes=0):
    # type: (str, str, str, int, int) -> AsyncGenerator[Dict[str, Any], None]
    """
    Fetches a table from the SNMP agent. Each value will be converted to a
    pure-python type.

    See :py:func:`puresnmp.api.raw.table` for more information of the returned
    structure.
    """
    if num_base_nodes:
        warn('Usage of "num_base_nodes" in table operations is no longer '
             'required', DeprecationWarning)
    else:
        parsed_oid = OID(oid)
        num_base_nodes = len(parsed_oid) + 1  # type: ignore
    tmp = raw.table(ip, community, oid, port=port,
                    num_base_nodes=num_base_nodes)
    async for row in tmp:
        index = row.pop('0')
        pythonized = {key: value.pythonize() for key, value in row.items()}
        pythonized['0'] = index
        yield pythonized


async def bulktable(ip, community, oid, port=161, num_base_nodes=0, bulk_size=10):
    # type: (str, str, str, int, int, int) -> AsyncGenerator[Dict[str, Any], None]
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
    for row in tmp:
        index = row.pop('0')
        pythonized = {key: value.pythonize() for key, value in row.items()}
        pythonized['0'] = index
        yield pythonized
