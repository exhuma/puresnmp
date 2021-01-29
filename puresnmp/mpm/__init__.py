"""
This module provides a plugin architecture for message-processing models (mpm).

Each mpm plugin can be distributed as separate package by providing
modules inside the namespace-package "puresnmp.mpm". Note that in order
to be a valid namespace-package, such a package *must not* have a
``__init__.py`` file!

Example folder-structure for a mpm plugin::

    my-security-plugin/
     +- setup.py (or pyproject.toml)
     +- puresnmp/
         +- mpm/
             +- mymodule.py
             +- myothermodule.py

Note that there is no ``__init__.py`` file!

In order for modules to be detected as plugin, they must follow the following
rules:

* Have a function ``create`` returning an instance of a class implementing the
  message-processing model. The function must take a network-transport handler
  and a "local configuration directory" as arguments. A reference
  implementation can be found in :py:class:`puresnmp.mpm.v3.V3MPM`.
* Contain a int-variable ``IDENTIFIER``. This variable should map to the
  message-processing model identifiers as defined in the SNMPv3 standard. See
  https://www.iana.org/assignments/snmp-number-spaces/snmp-number-spaces.xhtml
  and :rfc:`3411`
"""
import importlib
from threading import Lock
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Generic,
    NamedTuple,
    Optional,
    TypeVar,
)

from typing_extensions import Protocol

from puresnmp.credentials import Credentials
from puresnmp.exc import SnmpError
from puresnmp.pdu import PDU
from puresnmp.security import SecurityModel
from puresnmp.util import iter_namespace


class AbstractEncodingResult(NamedTuple):
    data: bytes
    security_model: Optional[SecurityModel[Any, Any]] = None


DISCOVERY_LOCK = Lock()
TEncodeResult = TypeVar("TEncodeResult", bound=AbstractEncodingResult)
TSecurityModel = TypeVar("TSecurityModel", bound=SecurityModel[Any, Any])


class TMPMPlugin(Protocol):
    """
    Protocol for the plugin factory function.
    """

    # pylint: disable=too-few-public-methods

    def create(
        self,
        transport_handler: Callable[[bytes], Awaitable[bytes]],
        lcd: Dict[str, Any],
    ) -> "MessageProcessingModel[TEncodeResult, TSecurityModel]":
        """
        See :py:func:`~.create`
        """
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


class MessageProcessingModel(Generic[TEncodeResult, TSecurityModel]):
    """
    Each Message Processing Model defines the format of a particular version of
    an SNMP message and coordinates the preparation and extraction of each such
    version-specific message format.

    See https://tools.ietf.org/html/rfc3411#section-6.2
    """

    IDENTIFIER: int
    disco: Optional[Any]

    def __init__(
        self,
        transport_handler: Callable[[bytes], Awaitable[bytes]],
        lcd: Dict[str, Any],
    ) -> None:
        self.transport_handler = transport_handler
        self.lcd = lcd
        self.disco = None
        self.security_model: Optional[TSecurityModel] = None

    async def encode(
        self,
        request_id: int,
        credentials: Credentials,
        engine_id: bytes,
        context_name: bytes,
        pdu: PDU,
    ) -> TEncodeResult:
        """
        Convert an SNMP PDU into raw bytes for the network.

        :param request_id: A unique ID for the request.
        :param credentials: Credentials which are used by the model if needed
            (encryption, authentication, ...).
        :param engine_id: The engine-id for use in SNMPv3.
            :py:mod:`puresnmp.util` contains helper methods to create those
            according to the RFC.
        :param context_name: An identifier for the SNMPv3 context
        :param pdu: The plain SNMP PDU to process
        :returns: Raw bytes that can be sent to the network
        """
        raise NotImplementedError(
            "encode is not yet implemented in %r" % type(self)
        )

    def decode(
        self,
        whole_msg: bytes,
        credentials: Credentials,
    ) -> PDU:
        """
        Convert bytes (as received raw from the network) into an SNMP PDU

        :param whole_msg: The message as received from the network
        :param credentials: Credentials which will be used if required by the
            model.
        :returns: A plain SNMP PDU
        """
        raise NotImplementedError(
            "decode is not yet implemented in %r" % type(self)
        )


def discover_plugins() -> None:
    """
    Load all privacy plugins into a global cache
    """

    if DISCOVERED_PLUGINS:
        return
    import puresnmp.mpm

    for _, name, _ in iter_namespace(puresnmp.mpm):
        mod = importlib.import_module(name)
        if not all(
            [
                hasattr(mod, "create"),
                hasattr(mod, "IDENTIFIER"),
            ]
        ):
            continue
        if mod.IDENTIFIER in DISCOVERED_PLUGINS:  # type: ignore
            raise ImportError(
                "Plugin %r causes a name-clash with the identifier %r. "
                "This is already used by %r"
                % (mod, mod.IDENTIFIER, DISCOVERED_PLUGINS[mod.IDENTIFIER])  # type: ignore
            )
        DISCOVERED_PLUGINS[mod.IDENTIFIER] = mod  # type: ignore


def create(
    identifier: int,
    transport_handler: Callable[[bytes], Awaitable[bytes]],
    lcd: Dict[str, Any],
) -> MessageProcessingModel[Any, Any]:
    """
    Creates a new instance of a message-processing-model

    :param identifier: The IANA ID for the message-processing model
    :param transport_handler: A callable that is responsible to send data to
        the network. It will be called with bytes to be sent, and should
        return bytes. It should by itself already be aware of *where* to send
        them.
    :param lcd: A "local configuration directory" which is dynamically
        updated with "discovery" data if required.
    :returns: A new Message Processing Model instance
    """
    # See https://tools.ietf.org/html/rfc3412#section-4.1.1

    with DISCOVERY_LOCK:
        discover_plugins()
    if identifier not in DISCOVERED_PLUGINS:
        raise UnknownMessageProcessingModel(identifier)

    mod = DISCOVERED_PLUGINS[identifier]
    return mod.create(transport_handler, lcd)
