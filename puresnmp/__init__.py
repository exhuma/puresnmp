from .x690.types import (
    GetNextRequest,
    GetRequest,
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
)
from .const import Version
from .transport import send, get_request_id


def get(ip: str, community: str, oid: str, version: bytes=Version.V2C,
        port: int=161):

    oid = ObjectIdentifier.from_string(oid)

    packet = Sequence(
        Integer(version),
        OctetString(community),
        GetRequest(oid, request_id=get_request_id())
    )

    response = send(ip, port, bytes(packet))
    ores = Sequence.from_bytes(response)
    result = ores.items[2].value
    return result.pythonize()


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
    if retrieved_oid not in oid:
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
        if not ores.items[2].value:  # TODO This index access is ugly!
            return
        response_object = ores.items[2]
        retrieved_oid = response_object.oid
        if retrieved_oid not in oid:
            return
