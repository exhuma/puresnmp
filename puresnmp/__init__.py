"""
This module contains the high-level functions to access the library. Care is
taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.
"""
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
    GetNextRequest,
    GetRequest,
    SetRequest,
    VarBind,
)
from .const import Version
from .transport import send, get_request_id


def get(ip: str, community: str, oid: str, version: bytes=Version.V2C,
        port: int=161):
    """
    Executes a simple SNMP GET request and returns a pure Python data structure.
    """
    return multiget(ip, community, [oid], version, port)[0]


def multiget(ip: str, community: str, oids: List[str],
             version: bytes=Version.V2C, port: int=161):
    """
    Executes an SNMP GET request with multiple OIDs and returns a list of pure
    Python objects. The order of the output items is the same order as the OIDs
    given as arguments.
    """

    oids = [ObjectIdentifier.from_string(oid) for oid in oids]

    packet = Sequence(
        Integer(version),
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


def getnext(ip, community, oid, version, port):
    """
    Executes a single SNMP GETNEXT request (used inside *walk*).
    """
    return multigetnext(ip, community, [oid], version, port)[0]


def multigetnext(ip, community, oids, version, port):
    """
    Function to send a single multi-oid GETNEXT request.
    """
    request = GetNextRequest(get_request_id(), *oids)
    packet = Sequence(
        Integer(version),
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


def walk(ip: str, community: str, oid, version: bytes=Version.V2C,
         port: int=161):
    """
    Executes a sequence of SNMP GETNEXT requests and returns an iterator over
    :py:class:`~puresnmp.pdu.VarBind` instances.
    """

    return multiwalk(ip, community, [oid], version, port)


def multiwalk(ip: str, community: str, oids: List[str],
              version: bytes=Version.V2C, port: int=161):
    """
    Executes a sequence of SNMP GETNEXT requests and returns an iterator over
    :py:class:`~puresnmp.pdu.VarBind` instances.
    """

    varbinds = multigetnext(ip, community, oids, version, port)

    retrieved_oids = [str(bind.oid) for bind in varbinds]
    prev_retrieved_oids = []
    while retrieved_oids:
        for bind in varbinds:
            yield bind

        varbinds = multigetnext(ip, community, retrieved_oids,
                                version, port)
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


def set(ip: str, community: str, oid: str, value: Type,
        version: bytes=Version.V2C, port: int=161):
    """
    Executes a simple SNMP SET request. The result is returned as pure Python
    data structure.
    """

    result = multiset(ip, community, [(oid, value)], version, port)
    return result[oid]


def multiset(ip: str, community: str, mappings: List[Tuple[str, Type]],
             version: bytes=Version.V2C, port: int=161):
    """

    Executes an SNMP SET request on multiple OIDs. The result is returned as
    pure Python data structure.
    """

    if any([not isinstance(v, Type) for k, v in mappings]):
        raise TypeError('SNMP requires typing information. The value for a '
                        '"set" request must be an instance of "Type"!')

    binds = [VarBind(ObjectIdentifier.from_string(k), v)
             for k, v in mappings]

    request = SetRequest(get_request_id(), binds)
    packet = Sequence(Integer(version),
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
