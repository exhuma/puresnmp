"""
This module contains the high-level functions to access the library. Care is
taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.
"""
from .x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
    Type,
)
from .exc import SnmpError
from .types import (
    GetNextRequest,
    GetRequest,
    SetRequest,
)
from .const import Version
from .transport import send, get_request_id


def get(ip: str, community: str, oid: str, version: bytes=Version.V2C,
        port: int=161):

    oid = ObjectIdentifier.from_string(oid)

    packet = Sequence(
        Integer(version),
        OctetString(community),
        GetRequest(get_request_id(), oid)
    )

    response = send(ip, port, bytes(packet))
    ores = Sequence.from_bytes(response)
    varbinds = ores.items[2].varbinds
    if len(varbinds) != 1:
        raise SnmpError('Unexpected response. Expected 1 varbind, but got %s!' %
                        len(varbinds))
    value = varbinds[0].value
    return value.pythonize()


def walk(ip: str, community: str, oid: str, version: bytes=Version.V2C,
         port: int=161):

    oid = ObjectIdentifier.from_string(oid)

    packet = Sequence(
        Integer(version),
        OctetString(community),
        GetNextRequest(oid, request_id=get_request_id())
    )

    response = send(ip, port, bytes(packet))
    ores = Sequence.from_bytes(response)
    response_object = ores.items[2]

    retrieved_oid = response_object.oid
    if retrieved_oid not in oid or retrieved_oid == oid:
        # the second test checks if we got the same OID back as we requested.
        # This usually points to an error (even if the error-code is not always
        # set!)
        return

    while retrieved_oid:
        yield response_object.oid, response_object.value
        packet = Sequence(
            Integer(version),
            OctetString(community),
            GetNextRequest(retrieved_oid, request_id=get_request_id())
        )

        response = send(ip, port, bytes(packet))
        ores = Sequence.from_bytes(response)
        response_object = ores.items[2]
        if retrieved_oid == response_object.oid:
            # If we got the same OID as the last request, we're likely finished.
            # Not all devices set an appropriate error-code as defined in the
            # RFC1157 Section 4.1.3, but at least guarantee this.
            return
        retrieved_oid = response_object.oid
        if retrieved_oid not in oid:
            return


def set(ip: str, community: str, oid: str, value: Type,
        version: bytes=Version.V2C, port: int=161):

    if not isinstance(value, Type):
        raise TypeError('SNMP requires typing information. The value for a '
                        '"set" request must be an instance of "Type"!')

    oid = ObjectIdentifier.from_string(oid)

    request = SetRequest(get_request_id(), oid, value)
    packet = Sequence(Integer(version),
                      OctetString(community),
                      request)
    response = send(ip, port, bytes(packet))
    ores = Sequence.from_bytes(response)
    result = ores.items[2].value
    return result.pythonize()