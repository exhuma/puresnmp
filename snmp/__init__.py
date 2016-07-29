from .x690.types import (
    GetRequest,
    Integer,
    Oid,
    Sequence,
    String,
)
from .const import Version
from .transport import send, get_request_id


def get(ip: str, community: str, oid: str, version: bytes=Version.V2C,
        port: int=161):

    oid = Oid.from_string(oid)

    packet = Sequence(
        Integer(version),
        String('public'),
        GetRequest(oid, request_id=get_request_id())
    )

    response = send(ip, port, bytes(packet))
    ores = Sequence.from_bytes(response)
    result = ores.items[2].value
    return result.pythonize()
