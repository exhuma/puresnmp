'''
This module contains a high-level API to SNMP functions.

The arguments and return values of these functions have types which are
internal to ``puresnmp`` (subclasses of :py:class:`puresnmp.x690.Type`).

Alternatively, there is :py:mod:`puresnmp.aio.api.pythonic` which converts
these values into pure Python types. This makes day-to-day programming a bit
easier but loses type information which may be useful in some edge-cases. In
such a case it's recommended to use :py:mod:`puresnmp.aio.api.raw`.
'''
from __future__ import unicode_literals

import logging
import sys
from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Tuple, cast, List
from warnings import warn

from ...const import DEFAULT_TIMEOUT, ERRORS_STRICT, ERRORS_WARN, Version
from ...exc import FaultySNMPImplementation, NoSuchOID, SnmpError
from ...pdu import (
    END_OF_MIB_VIEW,
    BulkGetRequest,
    GetNextRequest,
    GetRequest,
    GetResponse,
    SetRequest,
    VarBind
)
from ...typevars import PyType, TWrappedPyType
from ...util import BulkResult  # NOQA (must be here for type detection)
from ...util import get_unfinished_walk_oids, group_varbinds
from ...x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
    Type
)
from ...x690.util import tablify, to_bytes
from ..transport import Transport

if TYPE_CHECKING:  # pragma: no cover
    # pylint: disable=unused-import, invalid-name, ungrouped-imports
    from typing import Type as TType
    from typing import (
        AsyncGenerator,
        Callable,
        Coroutine,
        Dict,
        Set,
        TypeVar,
        Union,
    )
    TWalkResponse = AsyncGenerator[VarBind, None]
    TFetcher = Callable[[str, str, List[str], int, int],
                        Coroutine[Any, Any, List[VarBind]]]

try:
    unicode = unicode  # type: Callable[[Any], str]
except NameError:
    # pylint: disable=invalid-name
    unicode = str  # type: Callable[[Any], str]

_set = set

LOG = logging.getLogger(__name__)
OID = ObjectIdentifier.from_string


async def get(ip, community, oid, port=161, timeout=DEFAULT_TIMEOUT):
    # type: ( str, str, str, int, int ) -> Type[PyType]
    """
    Executes a simple SNMP GET request and returns a pure Python data
    structure.

    Example::

        >>> await get('192.168.1.1', 'private', '1.2.3.4')
        'non-functional example'
    """
    result = await multiget(
        ip, community, [oid], port, timeout=timeout)
    return result[0]


async def multiget(ip, community, oids, port=161, timeout=DEFAULT_TIMEOUT):
    # type: ( str, str, List[str], int, int ) -> List[Type[PyType]]
    """
    Executes an SNMP GET request with multiple OIDs and returns a list of pure
    Python objects. The order of the output items is the same order as the OIDs
    given as arguments.

    Example::

        >>> await multiget('192.168.1.1', 'private', ['1.2.3.4', '1.2.3.5'])
        ['non-functional example', 'second value']
    """
    transport = Transport(timeout=timeout)

    parsed_oids = [OID(oid) for oid in oids]

    packet = Sequence(
        Integer(Version.V2C),
        OctetString(community),
        GetRequest(transport.get_request_id(), *parsed_oids)
    )

    response = await transport.send(ip, port, to_bytes(packet))
    raw_response = cast(
        Tuple[Any, Any, GetResponse],
        Sequence.from_bytes(response)
    )

    output = [value for _, value in raw_response[2].varbinds]
    if len(output) != len(oids):
        raise SnmpError('Unexpected response. Expected %d varbind, '
                        'but got %d!' % (len(oids), len(output)))
    return output


async def getnext(ip, community, oid, port=161, timeout=DEFAULT_TIMEOUT):
    # type: (str, str, str, int, int) -> VarBind
    """
    Executes a single SNMP GETNEXT request (used inside *walk*).

    Example::

        >>> await getnext('192.168.1.1', 'private', '1.2.3')
        VarBind(ObjectIdentifier(1, 2, 3, 0), 'non-functional example')
    """
    result = await multigetnext(
        ip, community, [oid], port, timeout=timeout)
    return result[0]


async def multigetnext(ip, community, oids, port=161, timeout=DEFAULT_TIMEOUT):
    # type: (str, str, List[str], int, int) -> List[VarBind]
    """
    Executes a single multi-oid GETNEXT request.

    The request sends one packet to the remote host requesting the value of the
    OIDs following one or more given OIDs.

    Example::

        >>> await multigetnext('192.168.1.1', 'private', ['1.2.3', '1.2.4'])
        [
            VarBind(ObjectIdentifier(1, 2, 3, 0), 'non-functional example'),
            VarBind(ObjectIdentifier(1, 2, 4, 0), 'second value')
        ]
    """
    transport = Transport(timeout=timeout)
    request = GetNextRequest(transport.get_request_id(), *oids)
    packet = Sequence(
        Integer(Version.V2C),
        OctetString(community),
        request
    )
    response = await transport.send(ip, port, to_bytes(packet))
    raw_response = cast(
        Tuple[Any, Any, GetResponse],
        Sequence.from_bytes(response)
    )
    response_object = raw_response[2]
    if len(response_object.varbinds) != len(oids):
        raise SnmpError(
            'Invalid response! Expected exactly %d varbind, '
            'but got %d' % (len(oids), len(response_object.varbinds)))

    output = []
    for oid, value in response_object.varbinds:
        if value is END_OF_MIB_VIEW:
            break
        output.append(VarBind(oid, value))  # type: ignore

    # Verify that the OIDs we retrieved are successors of the requested OIDs.
    for requested, retrieved in zip(oids, output):
        if not OID(requested) < retrieved.oid:
            stringified = unicode(retrieved.oid)  # TODO remove when Py2 is dropped
            raise FaultySNMPImplementation(
                'The OID %s is not a successor of %s!' %
                (stringified, requested))
    return output


async def walk(ip, community, oid, port=161,
               timeout=DEFAULT_TIMEOUT, errors=ERRORS_STRICT):
    # type: (str, str, str, int, int, str) -> TWalkResponse
    """
    Executes a sequence of SNMP GETNEXT requests and returns a generator over
    :py:class:`~puresnmp.pdu.VarBind` instances.

    The generator stops when hitting an OID which is *not* a sub-node of the
    given start OID or at the end of the tree (whichever comes first).

    Example::

        >>> walk('127.0.0.1', 'private', '1.3.6.1.2.1.1')
        <async_generator object walk at 0x7fa2f775cf68>

        >>> from pprint import pprint
        >>> result = walk('127.0.0.1', 'private', '1.3.6.1.2.1.3')
        >>> res = []
        >>> async for x in gen:
        ...     res.append(x)
        ...
        >>> pprint(res)
        [VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 3, 1, 1, 1, 24, 1, 172, 17, 0, 1)), value=24),
         VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 3, 1, 1, 2, 24, 1, 172, 17, 0, 1)), value=b'\\x02B\\xef\\x14@\\xf5'),
         VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 3, 1, 1, 3, 24, 1, 172, 17, 0, 1)), value=64, b'\\xac\\x11\\x00\\x01')]
    """

    gen = multiwalk(ip, community, [oid], port, timeout=timeout, errors=errors)
    async for varbind in gen:
        yield varbind


async def multiwalk(
        ip, community, oids,
        port=161, timeout=DEFAULT_TIMEOUT, fetcher=multigetnext,
        errors=ERRORS_STRICT):
    # type: (str, str, List[str], int, int, TFetcher, str) -> TWalkResponse
    """
    Executes a sequence of SNMP GETNEXT requests and returns a generator over
    :py:class:`~puresnmp.pdu.VarBind` instances.

    This is the same as :py:func:`~.walk` except that it is capable of
    iterating over multiple OIDs at the same time.

    Example::

        >>> multiwalk('127.0.0.1', 'private', [
        ...     '1.3.6.1.2.1.1', '1.3.6.1.4.1.1'])
        <async_generator object multiwalk at 0x7fa2f775cf68>
    """
    LOG.debug('Walking on %d OIDs using %s', len(oids), fetcher.__name__)

    varbinds = await fetcher(ip, community, oids, port, timeout)
    requested_oids = [OID(oid) for oid in oids]
    grouped_oids = group_varbinds(varbinds, requested_oids)
    unfinished_oids = get_unfinished_walk_oids(grouped_oids)
    LOG.debug('%d of %d OIDs need to be continued',
              len(unfinished_oids),
              len(oids))
    yielded = _set([])  # type: ignore
    for var in sorted(grouped_oids.values()):
        for varbind in var:
            containment = [varbind.oid in _ for _ in requested_oids]
            if not any(containment) or varbind.oid in yielded:
                LOG.debug('Unexpected device response: Returned VarBind %s '
                          'was either not contained in the requested tree or '
                          'appeared more than once. Skipping!', varbind)
                continue
            yielded.add(varbind.oid)
            yield varbind

    # As long as we have unfinished OIDs, we need to continue the walk for
    # those.
    while unfinished_oids:
        next_fetches = [_[1].value.oid for _ in unfinished_oids]
        next_fetches_str = [unicode(_) for _ in next_fetches]
        try:
            varbinds = await fetcher(
                ip, community, next_fetches_str, port, timeout)
        except NoSuchOID:
            # Reached end of OID tree, finish iteration
            break
        except FaultySNMPImplementation as exc:
            if errors == ERRORS_WARN:
                LOG.warning('SNMP walk aborted prematurely due to faulty SNMP '
                            'implementation on device %r! Upon running a '
                            'GetNext on OIDs %r it returned the following '
                            'error: %s', ip, next_fetches_str, exc)
                break
            raise
        grouped_oids = group_varbinds(varbinds,
                                      next_fetches,
                                      user_roots=requested_oids)
        unfinished_oids = get_unfinished_walk_oids(grouped_oids)
        LOG.debug('%d of %d OIDs need to be continued',
                  len(unfinished_oids),
                  len(oids))
        for var in sorted(grouped_oids.values()):
            for varbind in var:
                containment = [varbind.oid in _ for _ in requested_oids]
                if not any(containment) or varbind.oid in yielded:
                    continue
                yielded.add(varbind.oid)
                yield varbind


async def set(ip, community, oid, value, port=161, timeout=DEFAULT_TIMEOUT):  # pylint: disable=redefined-builtin
    # type: (str, str, str, TWrappedPyType, int, int) -> TWrappedPyType
    """
    Executes a simple SNMP SET request. The result is returned as pure Python
    data structure. The value must be a subclass of
    :py:class:`~puresnmp.x690.types.Type`.

    Example::

        >>> await set('127.0.0.1', 'private', '1.3.6.1.2.1.1.4.0',
        ...     OctetString(b'I am contact'))
        b'I am contact'
    """

    result = await multiset(
        ip, community, [(oid, value)], port, timeout=timeout)
    return result[oid.lstrip('.')]


async def multiset(ip, community, mappings, port=161, timeout=DEFAULT_TIMEOUT):
    # type: (str, str, List[Tuple[str, TWrappedPyType]], int, int) -> Dict[str, TWrappedPyType]
    """
    Executes an SNMP SET request on multiple OIDs. The result is returned as
    pure Python data structure.

    Fake Example::

        >>> await multiset(
        ...     '127.0.0.1', 'private',
        ...     [('1.2.3', OctetString(b'foo')),
        ...     ('2.3.4', OctetString(b'bar'))])
        {'1.2.3': b'foo', '2.3.4': b'bar'}
    """
    transport = Transport(timeout=timeout)

    if any([not isinstance(v, Type) for k, v in mappings]):
        raise TypeError('SNMP requires typing information. The value for a '
                        '"set" request must be an instance of "Type"!')

    binds = [VarBind(OID(k), v)
             for k, v in mappings]

    request = SetRequest(transport.get_request_id(), binds)
    packet = Sequence(Integer(Version.V2C),
                      OctetString(community),
                      request)
    response = await transport.send(ip, port, to_bytes(packet))
    raw_response = cast(
        Tuple[Any, Any, GetResponse],
        Sequence.from_bytes(response)
    )
    output = {
        unicode(oid): value
        for oid, value in raw_response[2].varbinds
    }
    if len(output) != len(mappings):
        raise SnmpError('Unexpected response. Expected %d varbinds, '
                        'but got %d!' % (len(mappings), len(output)))
    return output


async def bulkget(
        ip, community, scalar_oids, repeating_oids, max_list_size=1,
        port=161, timeout=DEFAULT_TIMEOUT):
    # type: (str, str, List[str], List[str], int, int, int) -> BulkResult
    """
    Runs a "bulk" get operation and returns a :py:class:`~.BulkResult`
    instance.  This contains both a mapping for the scalar variables (the
    "non-repeaters") and an OrderedDict instance containing the remaining list
    (the "repeaters").

    The OrderedDict is ordered the same way as the SNMP response (whatever the
    remote device returns).

    This operation can retrieve both single/scalar values *and* lists of values
    ("repeating values") in one single request. You can for example retrieve
    the hostname (a scalar value), the list of interfaces (a repeating value)
    and the list of physical entities (another repeating value) in one single
    request.

    Note that this behaves like a **getnext** request for scalar values! So you
    will receive the value of the OID which is *immediately following* the OID
    you specified for both scalar and repeating values!

    :param scalar_oids: contains the OIDs that should be fetched as single
        value.
    :param repeating_oids: contains the OIDs that should be fetched as list.
    :param max_list_size: defines the max length of each list.

    Example::

        >>> ip = '192.168.1.1'
        >>> community = 'private'
        >>> result = await bulkget(
        ...     ip,
        ...     community,
        ...     scalar_oids=['1.3.6.1.2.1.1.1',
        ...                  '1.3.6.1.2.1.1.2'],
        ...     repeating_oids=['1.3.6.1.2.1.3.1',
        ...                     '1.3.6.1.2.1.5.1'],
        ...     max_list_size=10)
        BulkResult(
            scalars={'1.3.6.1.2.1.1.2.0': '1.3.6.1.4.1.8072.3.2.10',
                     '1.3.6.1.2.1.1.1.0': b'Linux aafa4dce0ad4 4.4.0-28-'
                                          b'generic #47-Ubuntu SMP Fri Jun 24 '
                                          b'10:09:13 UTC 2016 x86_64'},
            listing=OrderedDict([
                ('1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1', 10),
                ('1.3.6.1.2.1.5.1.0', b'\x01'),
                ('1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1', b'\x02B\x8e>\x9ee'),
                ('1.3.6.1.2.1.5.2.0', b'\x00'),
                ('1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1', b'\xac\x11\x00\x01'),
                ('1.3.6.1.2.1.5.3.0', b'\x00'),
                ('1.3.6.1.2.1.4.1.0', 1),
                ('1.3.6.1.2.1.5.4.0', b'\x01'),
                ('1.3.6.1.2.1.4.3.0', b'\x00\xb1'),
                ('1.3.6.1.2.1.5.5.0', b'\x00'),
                ('1.3.6.1.2.1.4.4.0', b'\x00'),
                ('1.3.6.1.2.1.5.6.0', b'\x00'),
                ('1.3.6.1.2.1.4.5.0', b'\x00'),
                ('1.3.6.1.2.1.5.7.0', b'\x00'),
                ('1.3.6.1.2.1.4.6.0', b'\x00'),
                ('1.3.6.1.2.1.5.8.0', b'\x00'),
                ('1.3.6.1.2.1.4.7.0', b'\x00'),
                ('1.3.6.1.2.1.5.9.0', b'\x00'),
                ('1.3.6.1.2.1.4.8.0', b'\x00'),
                ('1.3.6.1.2.1.5.10.0', b'\x00')]))
    """
    transport = Transport(timeout=timeout)

    scalar_oids = scalar_oids or []  # protect against empty values
    repeating_oids = repeating_oids or []  # protect against empty values

    oids = [
        OID(oid) for oid in scalar_oids
    ] + [
        OID(oid) for oid in repeating_oids
    ]

    non_repeaters = len(scalar_oids)

    packet = Sequence(
        Integer(Version.V2C),
        OctetString(community),
        BulkGetRequest(
            transport.get_request_id(), non_repeaters, max_list_size, *oids)
    )

    response = await transport.send(ip, port, to_bytes(packet))
    raw_response = cast(
        Tuple[Any, Any, GetResponse],
        Sequence.from_bytes(response)
    )

    # See RFC=3416 for details of the following calculation
    n = min(non_repeaters, len(oids))
    m = max_list_size
    r = max(len(oids) - n, 0)  # pylint: disable=invalid-name
    expected_max_varbinds = n + (m * r)

    _, _, get_response = raw_response
    n_retrieved_varbinds = len(get_response.varbinds)
    if n_retrieved_varbinds > expected_max_varbinds:
        raise SnmpError('Unexpected response. Expected no more than %d '
                        'varbinds, but got %d!' % (
                            expected_max_varbinds, n_retrieved_varbinds))

    # cut off the scalar OIDs from the listing(s)
    scalar_tmp = get_response.varbinds[0:len(scalar_oids)]
    repeating_tmp = get_response.varbinds[len(scalar_oids):]

    # prepare output for scalar OIDs
    scalar_out = {
        unicode(oid): value
        for oid, value in scalar_tmp
    }

    # prepare output for listing
    repeating_out = OrderedDict()  # type: Dict[str, Type]
    for oid, value in repeating_tmp:
        if value is END_OF_MIB_VIEW:
            break
        repeating_out[unicode(oid)] = value

    return BulkResult(scalar_out, repeating_out)


def _bulkwalk_fetcher(bulk_size=10):
    # type: (int) -> Callable[[str, str, List[str], int, int], Coroutine[ Any, Any, List[VarBind]]]
    """
    Create a bulk fetcher with a fixed limit on "repeatable" OIDs.
    """

    async def fetcher(ip, community, oids, port=161, timeout=DEFAULT_TIMEOUT):
        # type: (str, str, List[str], int, int) -> List[VarBind]
        '''
        Executes a SNMP BulkGet request.
        '''
        result = await bulkget(
            ip, community, [], oids,
            max_list_size=bulk_size,
            port=port, timeout=timeout)
        return [VarBind(OID(k), v)
                for k, v in result.listing.items()]

    if sys.version_info < (3, 0):
        fetcher.__name__ = str('_bulkwalk_fetcher(%d)' % bulk_size)
    else:
        fetcher.__name__ = '_bulkwalk_fetcher(%d)' % bulk_size
    return fetcher


async def bulkwalk(ip, community, oids, bulk_size=10, port=161,
                   timeout=DEFAULT_TIMEOUT):
    # type: (str, str, List[str], int, int, int) -> TWalkResponse
    """
    More efficient implementation of :py:func:`~.walk`. It uses
    :py:func:`~.bulkget` under the hood instead of :py:func:`~.getnext`.

    Just like :py:func:`~.multiwalk`, it returns a generator over
    :py:class:`~puresnmp.pdu.VarBind` instances.

    :param ip: The IP address of the target host.
    :param community: The community string for the SNMP connection.
    :param oids: A list of base OIDs to use in the walk operation.
    :param bulk_size: How many varbinds to request from the remote host with
        one request.
    :param port: The TCP port of the remote host.
    :param timeout: The TCP timeout for network calls

    Example::

        >>> from puresnmp.api.aio_raw import bulkwalk
        >>> ip = '127.0.0.1'
        >>> community = 'private'
        >>> oids = [
        ...     '1.3.6.1.2.1.2.2.1.2',   # name
        ...     '1.3.6.1.2.1.2.2.1.6',   # MAC
        ...     '1.3.6.1.2.1.2.2.1.22',  # ?
        ... ]
        >>> result = bulkwalk(ip, community, oids)
        >>> async for row in result:
        ...     print(row)
        VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1)), value=b'lo')
        VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 1)), value=b'')
        VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 22, 1)), value='0.0')
        VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 38)), value=b'eth0')
        VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 38)), value=b'\x02B\xac\x11\x00\x02')
        VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 22, 38)), value='0.0')
    """

    if not isinstance(oids, list):
        raise TypeError('OIDS need to be passed as list!')

    result = multiwalk(ip, community, oids, port=port,
                       fetcher=_bulkwalk_fetcher(bulk_size),
                       timeout=timeout)
    async for oid, value in result:
        yield VarBind(oid, value)  # type: ignore


async def table(ip, community, oid, port=161, num_base_nodes=0):
    # type: (str, str, str, int, int) -> List[Dict[str, Any]]
    """
    Fetch an SNMP table

    The resulting output will be a list of dictionaries where each dictionary
    corresponds to a row of the table.

    The index of the row will be contained in key ``'0'`` as a string
    representing an OID. This key ``'0'`` is automatically injected by
    ``puresnmp``. Table rows may or may not contain the row-index in other
    columns. This depends on the requested table.

    Each column ID is available as *string*.

    Example output (using fake data):

    >>> table('192.0.2.1', 'private', '1.3.6.1.2.1.2.2')
    [{'0': '1', '1': Integer(1), '2': Counter(30)},
     {'0': '2', '1': Integer(2), '2': Counter(123)}]
    """
    tmp = []  # type: List[Tuple[str, Type[Any]]]
    if num_base_nodes:
        warn('Usage of "num_base_nodes" in table operations is no longer '
             'required', DeprecationWarning)
    else:
        parsed_oid = OID(oid)
        num_base_nodes = len(parsed_oid) + 1  # type: ignore
    varbinds = walk(ip, community, oid, port=port)
    async for varbind in varbinds:
        tmp.append(varbind)  # type: ignore
    as_table = tablify(tmp, num_base_nodes=num_base_nodes)
    return as_table


async def bulktable(ip, community, oid, port=161, num_base_nodes=0, bulk_size=10):
    # type: (str, str, str, int, int, int) -> List[Dict[str, Any]]
    """
    Fetch an SNMP table using "bulk" requests.

    See :py:func:`.table` for more information of the returned structure.

    .. versionadded: 1.7.0
    """
    tmp_raw = []
    if num_base_nodes:
        warn('Usage of "num_base_nodes" in table operations is no longer '
             'required', DeprecationWarning)
    else:
        parsed_oid = OID(oid)
        num_base_nodes = len(parsed_oid) + 1  # type: ignore
    varbinds = bulkwalk(ip, community, [oid], port=port, bulk_size=bulk_size)
    async for varbind in varbinds:
        tmp_raw.append(varbind)
    tmp = cast(List[Tuple[Any, Any]], tmp_raw)
    as_table = tablify(tmp, num_base_nodes=num_base_nodes)
    return as_table
