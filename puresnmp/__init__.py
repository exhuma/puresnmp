"""
This module contains the high-level functions to access the library. Care is
taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.
"""
from .x690.types import (
    Integer,
    Null,
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


class SnmpClient(object):
    """
    SNMP client object used to send SNMP requests to target devices.
    """

    def __init__(self, community: str="public", version: bytes=Version.V2C, port: int=161, timeout: int=2):
        self.community = community
        self.version = version
        self.port = port
        self.timeout = timeout

    def get(self, ip: str, oid: str):
        """
        Executes a simple SNMP GET request and returns a pure Python data structure.
        """

        oid = ObjectIdentifier.from_string(oid)

        packet = Sequence(
            Integer(self.version),
            OctetString(self.community),
            GetRequest(get_request_id(), oid)
        )

        response = send(ip, self.port, bytes(packet), self.timeout)
        raw_response = Sequence.from_bytes(response)
        varbinds = raw_response[2].varbinds
        if len(varbinds) != 1:
            raise SnmpError('Unexpected response. Expected 1 varbind, but got %s!' %
                            len(varbinds))
        value = varbinds[0].value
        return value.pythonize()

    def _walk_internal(self, ip: str, oid: str):
        """
        Executes a single SNMP GETNEXT request (used inside *walk*).
        """
        request = GetNextRequest(get_request_id(), oid)
        packet = Sequence(
            Integer(self.version),
            OctetString(self.community),
            request
        )
        response = send(ip, self.port, bytes(packet), self.timeout)
        raw_response = Sequence.from_bytes(response)
        response_object = raw_response[2]
        return response_object

    def walk(self, ip: str, oid: str):
        """
        Executes a sequence of SNMP GETNEXT requests and returns an iterator over
        :py:class:`~puresnmp.pdu.VarBind` instances.
        """

        response_object = self._walk_internal(ip, oid)

        if len(response_object.varbinds) > 1:
            raise SnmpError('Unepexted response. Expected one varbind but got more')

        retrieved_oids = [str(bind.oid) for bind in response_object.varbinds]
        retrieved_oid = retrieved_oids[0]
        prev_retrieved_oid = None
        while retrieved_oid:
            for bind in response_object.varbinds:
                yield bind

            response_object = self._walk_internal(ip, retrieved_oid)
            retrieved_oids = [str(bind.oid) for bind in response_object.varbinds]
            retrieved_oid = retrieved_oids[0]

            # ending condition (check if we need to stop the walk)
            retrieved_oid_ = ObjectIdentifier.from_string(retrieved_oid)
            oid_ = ObjectIdentifier.from_string(oid)
            if retrieved_oid_ not in oid_ or retrieved_oid == prev_retrieved_oid:
                return

            prev_retrieved_oid = retrieved_oid

    def set(self, ip: str, oid: str, value: Type):
        """
        Executes a simple SNMP SET request. The result is returned as pure Python
        data structure.
        """

        if not isinstance(value, Type):
            raise TypeError('SNMP requires typing information. The value for a '
                            '"set" request must be an instance of "Type"!')

        oid = ObjectIdentifier.from_string(oid)

        request = SetRequest(get_request_id(), [VarBind(oid, value)])
        packet = Sequence(Integer(self.version),
                          OctetString(self.community),
                          request)
        response = send(ip, self.port, bytes(packet), self.timeout)
        raw_response = Sequence.from_bytes(response)
        varbinds = raw_response[2].varbinds
        if len(varbinds) != 1:
            raise SnmpError('Unexpected response. Expected 1 varbind, but got %s!' %
                            len(varbinds))
        value = varbinds[0].value
        return value.pythonize()
