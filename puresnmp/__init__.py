"""
This module contains the high-level functions to access the library. Care is
taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.
"""

# TODO (advanced): This module should not make use of it's own functions. The
#     module exists as an abstraction layer only. If one function uses a
#     "siblng" function, valuable information is lost. In general, this module
#     is beginning to be too "thick", containing too much business logic for a
#     mere abstraction layer.
from collections import OrderedDict, namedtuple
from typing import List, Tuple
import logging

from . import types  # NOQA (must be here for type detection)
from .x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
    Type,
)
from .x690.util import tablify
from .exc import SnmpError, NoSuchOID
from .pdu import (
    BulkGetRequest,
    GetNextRequest,
    GetRequest,
    SetRequest,
    VarBind,
)
from .const import Version
from .transport import send, get_request_id

_set = set


BulkResult = namedtuple('BulkResult', 'scalars listing')
WalkRow = namedtuple('WalkRow', 'value unfinished')
LOG = logging.getLogger(__name__)


def get(ip: str, community: str, oid: str, port: int=161):
    """
    Executes a simple SNMP GET request and returns a pure Python data structure.

    Example::

        >>> get('192.168.1.1', 'private', '1.2.3.4')
        'non-functional example'
    """
    return multiget(ip, community, [oid], port)[0]


def multiget(ip: str, community: str, oids: List[str], port: int=161):
    """
    Executes an SNMP GET request with multiple OIDs and returns a list of pure
    Python objects. The order of the output items is the same order as the OIDs
    given as arguments.

    Example::

        >>> multiget('192.168.1.1', 'private', ['1.2.3.4', '1.2.3.5'])
        ['non-functional example', 'second value']
    """

    oids = [ObjectIdentifier.from_string(oid) for oid in oids]

    packet = Sequence(
        Integer(Version.V2C),
        OctetString(community),
        GetRequest(get_request_id(), *oids)
    )

    response = send(ip, port, bytes(packet))
    raw_response = Sequence.from_bytes(response)

    output = [value.pythonize() for _, value in raw_response[2].varbinds]
    if len(output) != len(oids):
        raise SnmpError('Unexpected response. Expected %d varbind, '
                        'but got %d!' % (len(oids), len(output)))
    return output


def getnext(ip, community, oid, port=161):
    """
    Executes a single SNMP GETNEXT request (used inside *walk*).

    Example::

        >>> getnext('192.168.1.1', 'private', '1.2.3')
        VarBind(ObjectIdentifier(1, 2, 3, 0), 'non-functional example')
    """
    return multigetnext(ip, community, [oid], port)[0]


def multigetnext(ip, community, oids, port=161):
    """
    Function to send a single multi-oid GETNEXT request.

    The request sends one packet to the remote host requesting the value of the
    OIDs following one or more given OIDs.

    Example::

        >>> multigetnext('192.168.1.1', 'private', ['1.2.3', '1.2.4'])
        [
            VarBind(ObjectIdentifier(1, 2, 3, 0), 'non-functional example'),
            VarBind(ObjectIdentifier(1, 2, 4, 0), 'second value')
        ]
    """
    request = GetNextRequest(get_request_id(), *oids)
    packet = Sequence(
        Integer(Version.V2C),
        OctetString(community),
        request
    )
    response = send(ip, port, bytes(packet))
    raw_response = Sequence.from_bytes(response)
    response_object = raw_response[2]
    if len(response_object.varbinds) != len(oids):
        raise SnmpError(
            'Invalid response! Expected exactly %d varbind, '
            'but got %d' % (len(oids), len(response_object.varbinds)))
    return [VarBind(oid, value.pythonize())
            for oid, value in response_object.varbinds]


def walk(ip: str, community: str, oid, port: int=161):
    """
    Executes a sequence of SNMP GETNEXT requests and returns an generator over
    :py:class:`~puresnmp.pdu.VarBind` instances.

    The generator stops when hitting an OID which is *not* a sub-node of the
    given start OID or at the end of the tree (whichever comes first).

    Example::

        >>> walk('127.0.0.1', 'private', '1.3.6.1.2.1.1')
        <generator object multiwalk at 0x7fa2f775cf68>

        >>> from pprint import pprint
        >>> pprint(list(walk('127.0.0.1', 'private', '1.3.6.1.2.1.3')))
        [VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 3, 1, 1, 1, 24, 1, 172, 17, 0, 1)), value=24),
         VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 3, 1, 1, 2, 24, 1, 172, 17, 0, 1)), value=b'\\x02B\\xef\\x14@\\xf5'),
         VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 3, 1, 1, 3, 24, 1, 172, 17, 0, 1)), value=64, b'\\xac\\x11\\x00\\x01')]
    """

    return multiwalk(ip, community, [oid], port)


def unzip_walk_result(varbinds, base_ids):
    """
    Takes a list of varbinds and a list of base OIDs and returns a mapping from
    those base IDs to lists of varbinds.
    """
    n = len(base_ids)
    results = {}
    for i in range(n):
        results[base_ids[i]] = varbinds[i::n]
    return results


def get_unfinished_walk_oids(varbinds, requested_oids, bases=None):

    # split result into a list for each requested base OID
    results = unzip_walk_result(varbinds, requested_oids)

    # Sometimes (for continued walk requests), the requested OIDs are actually
    # children of the originally requested OIDs on the second and subsequent
    # requests. If *bases* is set, it will contain the originally requested OIDs
    # and we need to replace the dict keys with the appropriate bases.
    if bases:
        new_results = {}
        for k, v in results.items():
            containment = [base for base in bases if k in base]
            if len(containment) > 1:
                raise RuntimeError('Unexpected OID result. A value was '
                                   'contained in more than one base than '
                                   'should be possible!')
            if not containment:
                continue
            new_results[containment[0]] = v
            results = new_results

    # we now have a list of values for each requested OID and need to determine
    # if we need to continue fetching: Inspect the last item of each list if
    # those OIDs are still children of the requested IDs we need to continue
    # fetching using *those* IDs (as we're using GetNext behaviour). If they are
    # *not* children of the requested OIDs, we went too far (in the case of a
    # bulk operation) and need to remove all outliers.
    #
    # The above behaviour is the same for both bulk and simple operations. For
    # simple operations we simply have a list of 1 element per OID, but the
    # behaviour is identical

    # Build a mapping from the originally requested OID to the last fetched OID
    # from that tree.
    last_received_oids = {k: WalkRow(v[-1], v[-1].oid in k)
                          for k, v in results.items()}

    output = [item for item in last_received_oids.items() if item[1].unfinished]
    return output


def multiwalk(ip: str, community: str, oids: List[str], port: int=161,
              fetcher=multigetnext):
    """
    Executes a sequence of SNMP GETNEXT requests and returns an generator over
    :py:class:`~puresnmp.pdu.VarBind` instances.

    This is the same as :py:func:`~.walk` except that it is capable of iterating
    over multiple OIDs at the same time.

    Example::

        >>> walk('127.0.0.1', 'private', ['1.3.6.1.2.1.1', '1.3.6.1.4.1.1'])
        <generator object multiwalk at 0x7fa2f775cf68>
    """
    LOG.debug('Walking on %d OIDs using %s', len(oids), fetcher.__name__)

    varbinds = fetcher(ip, community, oids, port)
    requested_oids = [ObjectIdentifier.from_string(oid) for oid in oids]
    unfinished_oids = get_unfinished_walk_oids(varbinds, requested_oids)
    LOG.debug('%d of %d OIDs need to be continued',
              len(unfinished_oids),
              len(oids))
    output = unzip_walk_result(varbinds, requested_oids)

    # As long as we have unfinished OIDs, we need to continue the walk for
    # those.
    while unfinished_oids:
        next_fetches = [_[1].value.oid for _ in unfinished_oids]
        try:
            varbinds = fetcher(ip, community, [str(_) for _ in next_fetches],
                               port)
        except NoSuchOID:
            # Reached end of OID tree, finish iteration
            break
        unfinished_oids = get_unfinished_walk_oids(varbinds, next_fetches,
                                                   bases=requested_oids)
        LOG.debug('%d of %d OIDs need to be continued',
                  len(unfinished_oids),
                  len(oids))
        for k, v in unzip_walk_result(varbinds, next_fetches).items():
            for ko, vo in output.items():
                if k in ko:
                    vo.extend(v)

    yielded = _set([])
    for v in output.values():
        for varbind in v:
            containment = [varbind.oid in _ for _ in requested_oids]
            if not any(containment) or varbind.oid in yielded:
                continue
            yielded.add(varbind.oid)
            yield varbind


def set(ip: str, community: str, oid: str, value: Type, port: int=161):
    """
    Executes a simple SNMP SET request. The result is returned as pure Python
    data structure. The value must be a subclass of
    :py:class:`~puresnmp.x690.types.Type`.

    Example::

        >>> set('127.0.0.1', 'private', '1.3.6.1.2.1.1.4.0',
        ...     OctetString(b'I am contact'))
        b'I am contact'
    """

    result = multiset(ip, community, [(oid, value)], port)
    return result[oid]


def multiset(ip: str, community: str, mappings: List[Tuple[str, Type]],
             port: int=161):
    """

    Executes an SNMP SET request on multiple OIDs. The result is returned as
    pure Python data structure.

    Fake Example::

        >>> multiset('127.0.0.1', 'private', [('1.2.3', OctetString(b'foo')),
        ...                                   ('2.3.4', OctetString(b'bar'))])
        {'1.2.3': b'foo', '2.3.4': b'bar'}
    """

    if any([not isinstance(v, Type) for k, v in mappings]):
        raise TypeError('SNMP requires typing information. The value for a '
                        '"set" request must be an instance of "Type"!')

    binds = [VarBind(ObjectIdentifier.from_string(k), v)
             for k, v in mappings]

    request = SetRequest(get_request_id(), binds)
    packet = Sequence(Integer(Version.V2C),
                      OctetString(community),
                      request)
    response = send(ip, port, bytes(packet))
    raw_response = Sequence.from_bytes(response)
    output = {
        str(oid): value.pythonize() for oid, value in raw_response[2].varbinds
    }
    if len(output) != len(mappings):
        raise SnmpError('Unexpected response. Expected %d varbinds, '
                        'but got %d!' % (len(mappings), len(output)))
    return output


def bulkget(ip, community, scalar_oids, repeating_oids, max_list_size=1,
            port=161):
    """
    Runs a "bulk" get operation and returns a :py:class:`~.BulkResult` instance.
    This contains both a mapping for the scalar variables (the "non-repeaters")
    and an OrderedDict instance containing the remaining list (the "repeaters").

    The OrderedDict is ordered the same way as the SNMP response (whatever the
    remote device returns).

    This operation can retrieve both single/scalar values *and* lists of values
    ("repeating values") in one single request. You can for example retrieve the
    hostname (a scalar value), the list of interfaces (a repeating value) and
    the list of physical entities (another repeating value) in one single
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
        >>> result = bulkget(ip,
        ...                  community,
        ...                  scalar_oids=['1.3.6.1.2.1.1.1',
        ...                               '1.3.6.1.2.1.1.2'],
        ...                  repeating_oids=['1.3.6.1.2.1.3.1',
        ...                                  '1.3.6.1.2.1.5.1'],
        ...                  max_list_size=10)
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

    scalar_oids = scalar_oids or []  # protect against empty values
    repeating_oids = repeating_oids or []  # protect against empty values

    oids = [
        ObjectIdentifier.from_string(oid) for oid in scalar_oids
    ] + [
        ObjectIdentifier.from_string(oid) for oid in repeating_oids
    ]

    non_repeaters = len(scalar_oids)

    packet = Sequence(
        Integer(Version.V2C),
        OctetString(community),
        BulkGetRequest(get_request_id(), non_repeaters, max_list_size, *oids)
    )

    response = send(ip, port, bytes(packet))
    raw_response = Sequence.from_bytes(response)

    # See RFC=3416 for details of the following calculation
    n = min(non_repeaters, len(oids))
    m = max_list_size
    r = max(len(oids) - n, 0)
    expected_max_varbinds = n + (m * r)

    if len(raw_response[2].varbinds) > expected_max_varbinds:
        raise SnmpError('Unexpected response. Expected no more than %d '
                        'varbinds, but got %d!' % (
                            expected_max_varbinds, len(oids)))

    # cut off the scalar OIDs from the listing(s)
    scalar_tmp = raw_response[2].varbinds[0:len(scalar_oids)]
    repeating_tmp = raw_response[2].varbinds[len(scalar_oids):]

    # prepare output for scalar OIDs
    scalar_out = {str(oid): value.pythonize() for oid, value in scalar_tmp}

    # prepare output for listing
    repeating_out = OrderedDict()
    for oid, value in repeating_tmp:
        repeating_out[str(oid)] = value.pythonize()

    return BulkResult(scalar_out, repeating_out)


def bulkwalk_fetcher(bulk_size=10):
    """
    Create a bulk fetcher with a fixed limit on "repeatable" OIDs.
    """
    def fun(ip, community, oids, port=161):
        result = bulkget(ip, community, [], oids, max_list_size=bulk_size,
                         port=port)
        return [VarBind(ObjectIdentifier.from_string(k), v)
                for k, v in result.listing.items()]
    fun.__name__ = 'bulkwalk_fetcher(%d)' % bulk_size
    return fun


def bulkwalk(ip, community, oids, bulk_size=10, port=161):
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

    Example::

        >>> from puresnmp import bulkwalk
        >>> ip = '127.0.0.1'
        >>> community = 'private'
        >>> oids = [
        ...     '1.3.6.1.2.1.2.2.1.2',   # name
        ...     '1.3.6.1.2.1.2.2.1.6',   # MAC
        ...     '1.3.6.1.2.1.2.2.1.22',  # ?
        ... ]
        >>> result = bulkwalk(ip, community, oids)
        >>> for row in result:
        ...     print(row)
        VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1)), value=b'lo')
        VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 1)), value=b'')
        VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 22, 1)), value='0.0')
        VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 38)), value=b'eth0')
        VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 38)), value=b'\x02B\xac\x11\x00\x02')
        VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 22, 38)), value='0.0')
    """

    result = multiwalk(ip, community, oids, port=161,
                       fetcher=bulkwalk_fetcher(bulk_size))
    for oid, value in result:
        yield VarBind(oid, value)


def table(ip: str, community: str, oid: str, port: int=161,
          num_base_nodes: int=0):
    """
    Run a series of GETNEXT requests on an OID and construct a table from the
    result.

    The table is a row of dicts. The key of each dict is the row ID. By default
    that is the **last** node of the OID tree.

    If the rows are identified by multiple nodes, you need to secify the base by
    setting *walk* to a non-zero value.
    """
    tmp = walk(ip, community, oid, port=port)
    as_table = tablify(tmp, num_base_nodes=num_base_nodes)
    return as_table
