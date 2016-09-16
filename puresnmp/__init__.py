"""
This module contains the high-level functions to access the library. Care is
taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.
"""
from typing import List

from .x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
    Type,
)
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

    oid = ObjectIdentifier.from_string(oid)

    packet = Sequence(
        Integer(version),
        OctetString(community),
        GetRequest(get_request_id(), oid)
    )

    response = send(ip, port, bytes(packet))
    raw_response = Sequence.from_bytes(response)
    varbinds = raw_response[2].varbinds
    if len(varbinds) != 1:
        raise SnmpError('Unexpected response. Expected 1 varbind, but got %s!' %
                        len(varbinds))
    value = varbinds[0].value
    return value.pythonize()


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
    return output


def _walk_internal(ip, community, oid, version, port):
    """
    Executes a single SNMP GETNEXT request (used inside *walk*).
    """
    request = GetNextRequest(get_request_id(), oid)
    packet = Sequence(
        Integer(version),
        OctetString(community),
        request
    )
    response = send(ip, port, bytes(packet))
    raw_response = Sequence.from_bytes(response)
    response_object = raw_response[2]
    return response_object


def _multiwalk_internal(ip, community, oids, version, port):
    """
    Function to send a single multi-oid GETNEXT request.
    """
    # TODO This can be merged with _walk_internal
    request = GetNextRequest(get_request_id(), *oids)
    packet = Sequence(
        Integer(version),
        OctetString(community),
        request
    )
    response = send(ip, port, bytes(packet))
    raw_response = Sequence.from_bytes(response)
    response_object = raw_response[2]
    return response_object


def walk(ip: str, community: str, oid, version: bytes=Version.V2C,
         port: int=161):
    """
    Executes a sequence of SNMP GETNEXT requests and returns an iterator over
    :py:class:`~puresnmp.pdu.VarBind` instances.
    """

    response_object = _walk_internal(ip, community, oid, version, port)

    if len(response_object.varbinds) > 1:
        raise SnmpError('Unepexted response. Expected one varbind but got more')

    retrieved_oids = [str(bind.oid) for bind in response_object.varbinds]
    retrieved_oid = retrieved_oids[0]
    prev_retrieved_oid = None
    while retrieved_oid:
        for bind in response_object.varbinds:
            yield bind

        response_object = _walk_internal(ip, community, retrieved_oid,
                                         version, port)
        retrieved_oids = [str(bind.oid) for bind in response_object.varbinds]
        retrieved_oid = retrieved_oids[0]

        # ending condition (check if we need to stop the walk)
        retrieved_oid_ = ObjectIdentifier.from_string(retrieved_oid)
        oid_ = ObjectIdentifier.from_string(oid)
        if retrieved_oid_ not in oid_ or retrieved_oid == prev_retrieved_oid:
            return

        prev_retrieved_oid = retrieved_oid


def multiwalk(ip: str, community: str, oids: List[str],
              version: bytes=Version.V2C, port: int=161):
    """
    Executes a sequence of SNMP GETNEXT requests and returns an iterator over
    :py:class:`~puresnmp.pdu.VarBind` instances.
    """

    # TODO: This should be mergeable with the simple "walk" function.

    response_object = _multiwalk_internal(ip, community, oids, version, port)

    retrieved_oids = [str(bind.oid) for bind in response_object.varbinds]
    prev_retrieved_oids = []
    while retrieved_oids:
        for bind in response_object.varbinds:
            yield bind

        response_object = _multiwalk_internal(ip, community, retrieved_oids,
                                              version, port)
        retrieved_oids = [str(bind.oid) for bind in response_object.varbinds]

        # ending condition (check if we need to stop the walk)
        retrieved_oids_ = [ObjectIdentifier.from_string(_)
                           for _ in retrieved_oids]
        requested_oids = [ObjectIdentifier.from_string(_)
                          for _ in oids]
        contained_oids = [a in b for a, b in zip(retrieved_oids_, requested_oids)]
        if not all(contained_oids) or retrieved_oids == prev_retrieved_oids:
            return

        prev_retrieved_oids = retrieved_oids


def set(ip: str, community: str, oid: str, value: Type,
        version: bytes=Version.V2C, port: int=161):
    """
    Executes a simple SNMP SET request. The result is returned as pure Python
    data structure.
    """

    if not isinstance(value, Type):
        raise TypeError('SNMP requires typing information. The value for a '
                        '"set" request must be an instance of "Type"!')

    oid = ObjectIdentifier.from_string(oid)

    request = SetRequest(get_request_id(), [VarBind(oid, value)])
    packet = Sequence(Integer(version),
                      OctetString(community),
                      request)
    response = send(ip, port, bytes(packet))
    raw_response = Sequence.from_bytes(response)
    varbinds = raw_response[2].varbinds
    if len(varbinds) != 1:
        raise SnmpError('Unexpected response. Expected 1 varbind, but got %s!' %
                        len(varbinds))
    value = varbinds[0].value
    return value.pythonize()
