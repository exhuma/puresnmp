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

from .x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
    Type,
)
from .x690.util import tablify
from .exc import SnmpError
from .pdu import (
    BulkGetRequest,
    GetNextRequest,
    GetRequest,
    SetRequest,
    VarBind,
)
from .const import Version
from .transport import send, get_request_id


BulkResult = namedtuple('BulkResult', 'scalars listing')


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


def getnext(ip, community, oid, port):
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
    return response_object.varbinds


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
        [VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 3, 1, 1, 1, 24, 1, 172, 17, 0, 1)), value=Integer(24)),
         VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 3, 1, 1, 2, 24, 1, 172, 17, 0, 1)), value=OctetString(b'\\x02B\\xef\\x14@\\xf5')),
         VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 3, 1, 1, 3, 24, 1, 172, 17, 0, 1)), value=NonASN1Type(64, b'\\xac\\x11\\x00\\x01'))]
    """

    return multiwalk(ip, community, [oid], port)


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

    varbinds = fetcher(ip, community, oids, port)

    retrieved_oids = [str(bind.oid) for bind in varbinds]
    prev_retrieved_oids = []
    while retrieved_oids:
        for bind in varbinds:
            yield bind

        varbinds = fetcher(ip, community, retrieved_oids, port)
        retrieved_oids = [str(bind.oid) for bind in varbinds]

        # ending condition (check if we need to stop the walk)
        retrieved_oids_ = [ObjectIdentifier.from_string(_)
                           for _ in retrieved_oids]
        requested_oids = [ObjectIdentifier.from_string(_)
                          for _ in oids]
        contained_oids = [
            a in b for a, b in zip(retrieved_oids_, requested_oids)]
        if not all(contained_oids) or retrieved_oids == prev_retrieved_oids:
            return

        prev_retrieved_oids = retrieved_oids


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
