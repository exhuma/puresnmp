import importlib
import pkgutil
from typing import Any, Awaitable, Callable, Dict, NamedTuple, Optional, Tuple

from typing_extensions import Protocol

import puresnmp.mpm
from puresnmp.adt import V3Flags
from puresnmp.credentials import Credentials
from puresnmp.exc import SnmpError
from puresnmp.pdu import PDU
from puresnmp.security import SecurityModel
from puresnmp.security.usm import DiscoData  # TODO: Too specific to USM


class TMPMPlugin(Protocol):
    def create(
        self,
        transport_handler: Callable[[bytes], Awaitable[bytes]],
        lcd: Dict[str, Any],
    ) -> "MessageProcessingModel":
        ...


#: Global registry of detected plugins
DISCOVERED_PLUGINS: Dict[int, TMPMPlugin] = {}


class MPMException(SnmpError):
    """
    Base class for message-processing model related errors
    """


class UnknownMessageProcessingModel(MPMException):
    """
    Exception which is raised when working with an unsupported/unknown
    message-processing model
    """

    def __init__(self, identifier: int) -> None:
        super().__init__(
            f"Unknown message processing model with ID: {identifier}"
        )


class PreparedData(NamedTuple):
    security_model: SecurityModel
    security_name: bytes
    security_level: "V3Flags"
    context_engine_id: bytes
    context_name: bytes
    pdu_version: int
    pdu: PDU
    pdu_type: int
    max_size_response_scoped_pdu: int
    status_information: int
    state_reference: Any


class MessageProcessingModel:
    """
    Each Message Processing Model defines the format of a particular version of
    an SNMP message and coordinates the preparation and extraction of each such
    version-specific message format.

    See https://tools.ietf.org/html/rfc3411#section-6.2
    """

    IDENTIFIER: int
    disco: Optional[DiscoData]

    def __init__(
        self,
        transport_handler: Callable[[bytes], Awaitable[bytes]],
        lcd: Dict[str, Any],
    ) -> None:
        self.transport_handler = transport_handler
        self.lcd = lcd
        self.disco = None
        self.security_model: Optional[SecurityModel] = None

    async def encode(
        self,
        request_id: int,
        credentials: Credentials,
        engine_id: bytes,
        context_name: bytes,
        pdu,
    ) -> Tuple[bytes, Optional[SecurityModel]]:
        raise NotImplementedError(
            "encode is not yet implemented in %r" % type(self)
        )

    def decode(
        self,
        whole_msg,  # as received from the network
        credentials: Optional[Credentials] = None,
    ) -> PDU:
        raise NotImplementedError(
            "decode is not yet implemented in %r" % type(self)
        )

    def prepare_outgoing_message(
        self,
        message_id: int,
        security_model: SecurityModel,  # Security Model to use
        security_name,  # on behalf of this principal
        security_level,  # Level of Security requested
        context_engine_id,  # data from/at this entity
        context_name,  # data from/in this context
        pdu_version,  # the version of the PDU
        pdu,  # SNMP Protocol Data Unit
        expect_response,  # TRUE or FALSE
    ) -> bytes:
        raise NotImplementedError(
            "prepare_outgoing_message is not yet implemented in %r" % type(self)
        )

    def prepare_data_elements(
        self,
        whole_msg,  # as received from the network
        security_model: SecurityModel,
    ) -> PreparedData:
        """
        The Message Processing Subsystem provides this service primitive for
        preparing the abstract data elements from an incoming SNMP message:
        """
        # XXX TODO should raise "SnmpFailure" on error
        raise NotImplementedError(
            "prepare_data_elements is not yet implemented in %r" % type(self)
        )


def iter_namespace(ns_pkg):
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")


def discover_plugins():
    for _, name, _ in iter_namespace(puresnmp.mpm):
        mod = importlib.import_module(name)
        if not all(
            [
                hasattr(mod, "create"),
                hasattr(mod, "IDENTIFIER"),
            ]
        ):
            continue
        if mod.IDENTIFIER in DISCOVERED_PLUGINS:
            raise ImportError(
                "Plugin %r causes a name-clash with the identifier %r. This is already used by %r"
                % (mod, mod.IDENTIFIER, DISCOVERED_PLUGINS[mod.IDENTIFIER])
            )
        DISCOVERED_PLUGINS[mod.IDENTIFIER] = mod


def create(
    identifier: int,
    transport_handler: Callable[[bytes], Awaitable[bytes]],
    lcd: Dict[str, Any],
) -> MessageProcessingModel:
    # See https://tools.ietf.org/html/rfc3412#section-4.1.1

    if not DISCOVERED_PLUGINS:
        discover_plugins()
    if identifier not in DISCOVERED_PLUGINS:
        raise UnknownMessageProcessingModel(identifier)
    mod = DISCOVERED_PLUGINS[identifier]
    return mod.create(transport_handler, lcd)
