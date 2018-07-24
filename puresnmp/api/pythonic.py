"""
This module contains the high-level functions to access the library. Care is
taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.

This module provides "syntactic sugar" around the lower-level, but almost
identical, module :py:mod:`puresnmp.api.raw`. The "raw" module returns the
variable types unmodified which are all subclasses of
:py:class:`puresnmp.x690.types.Type`.
"""

# TODO (advanced): This module should not make use of it's own functions. The
#     is beginning to be too "thick", containing too much business logic for a
#     mere abstraction layer.
#     module exists as an abstraction layer only. If one function uses a
#     "siblng" function, valuable information is lost. In general, this module


import logging
from collections import OrderedDict
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from . import raw
from ..pdu import VarBind
from ..util import BulkResult
from ..x690.util import tablify

if TYPE_CHECKING:  # pragma: no cover
    # pylint: disable=unused-import, invalid-name
    from typing import Any, Callable, Dict, Generator, List, Tuple, Union
    from ..x690.types import Type
    Pythonized = Union[str, bytes, int, datetime, timedelta]

try:
    unicode  # type: Callable[[Any], str]
except NameError:
    # pylint: disable=invalid-name
    unicode = str  # type: Callable[[Any], str]

_set = set
LOG = logging.getLogger(__name__)


def get(ip, community, oid, port=161, timeout=2):
    # type: (str, str, str, int, int) -> Pythonized
    """
    Delegates to :py:func:`~puresnmp.api.raw.get` but returns simple Python
    types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    raw_value = raw.get(ip, community, oid, port, timeout=timeout)
    return raw_value.pythonize()


def multiget(ip, community, oids, port=161, timeout=2):
    # type: (str, str, List[str], int, int) -> List[Pythonized]
    """
    Delegates to :py:func:`~puresnmp.api.raw.multiget` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    raw_output = raw.multiget(ip, community, oids, port, timeout)
    pythonized = [value.pythonize() for value in raw_output]
    return pythonized


def getnext(ip, community, oid, port=161, timeout=2):
    # type: (str, str, str, int, int) -> VarBind
    """
    Delegates to :py:func:`~puresnmp.api.raw.getnext` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    return multigetnext(ip, community, [oid], port, timeout=timeout)[0]


def multigetnext(ip, community, oids, port=161, timeout=2):
    # type: (str, str, List[str], int, int) -> List[VarBind]
    """
    Delegates to :py:func:`~puresnmp.api.raw.multigetnext` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    raw_output = raw.multigetnext(ip, community, oids, port, timeout)
    pythonized = [VarBind(oid, value.pythonize()) for oid, value in raw_output]
    return pythonized


def walk(ip, community, oid, port=161, timeout=2):
    # type: (str, str, str, int, int) -> Generator[VarBind, None, None]
    """
    Delegates to :py:func:`~puresnmp.api.raw.walk` but returns simple Python
    types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    raw_result = raw.walk(ip, community, oid, port, timeout)
    for raw_oid, raw_value in raw_result:
        yield VarBind(raw_oid, raw_value.pythonize())


def multiwalk(ip, community, oids, port=161, timeout=2,
              fetcher=raw.multigetnext):
    # type: (str, str, List[str], int, int, Callable[[str, str, List[str], int, int], List[VarBind]]) -> Generator[VarBind, None, None]
    """
    Delegates to :py:func:`~puresnmp.api.raw.multiwalk` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """
    raw_output = raw.multiwalk(ip, community, oids, port, timeout, fetcher)
    for oid, value in raw_output:
        yield VarBind(oid, value.pythonize())


def set(ip, community, oid, value, port=161, timeout=2):  # pylint: disable=redefined-builtin
    # type: (str, str, str, Type, int, int) -> Type
    """
    Delegates to :py:func:`~puresnmp.api.raw.set` but returns simple Python
    types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    result = multiset(ip, community, [(oid, value)], port, timeout=timeout)
    return result[oid]


def multiset(ip, community, mappings, port=161, timeout=2):
    # type: (str, str, List[Tuple[str, Type]], int, int) -> Dict[str, Type]
    """
    Delegates to :py:func:`~puresnmp.api.raw.multiset` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    raw_output = raw.multiset(ip, community, mappings, port, timeout)
    pythonized = {unicode(oid): value.pythonize()
                  for oid, value in raw_output.items()}
    return pythonized


def bulkget(ip, community, scalar_oids, repeating_oids, max_list_size=1,
            port=161, timeout=2):
    # type: (str, str, List[str], List[str], int, int, int) -> BulkResult
    """
    Delegates to :py:func:`~puresnmp.api.raw.mulkget` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    raw_output = raw.bulkget(ip, community, scalar_oids, repeating_oids,
                             max_list_size=max_list_size,
                             port=port,
                             timeout=timeout)
    pythonized_scalars = {oid: value.pythonize()
                          for oid, value in raw_output.scalars.items()}
    pythonized_list = OrderedDict(
        [(oid, value.pythonize())
         for oid, value in raw_output.listing.items()])
    return BulkResult(pythonized_scalars, pythonized_list)


def bulkwalk(ip, community, oids, bulk_size=10, port=161):
    # type: (str, str, List[str], int, int) -> Generator[VarBind, None, None]
    """
    Delegates to :py:func:`~puresnmp.api.raw.bulkwalk` but returns simple
    Python types.

    See the "raw" equivalent for detailed documentation & examples.
    """

    result = multiwalk(
        ip, community, oids, port=port,
        fetcher=raw._bulkwalk_fetcher(bulk_size))  # pylint: disable=protected-access
    for oid, value in result:
        yield VarBind(oid, value)


def table(ip, community, oid, port=161, num_base_nodes=0):
    # type (str, str, str, int, int) ->
    """
    Converts a "walk" result into a pseudo-table. See
    :py:func:`puresnmp.api.raw.table` for more information.
    """
    tmp = walk(ip, community, oid, port=port)
    as_table = tablify(tmp, num_base_nodes=num_base_nodes)
    return as_table
