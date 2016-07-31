from .x690.types import (
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
        OctetString('public'),
        GetRequest(oid, request_id=get_request_id())
    )

    response = send(ip, port, bytes(packet))
    ores = Sequence.from_bytes(response)
    result = ores.items[2].value
    return result.pythonize()
