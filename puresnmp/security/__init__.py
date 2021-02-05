"""
This module provides a plugin architecture for security methods.

Each security plugin can be distributed as separate package by providing
modules inside the namespace-package "puresnmp.security". Note that in order
to be a valid namespace-package, such a package *must not* have a
``__init__.py`` file!

Example folder-structure for a privacy plugin:

.. code-block:: text

    my-security-plugin/
     +- setup.py (or pyproject.toml)
     +- puresnmp/
         +- security/
             +- mymodule.py
             +- myothermodule.py

Note that there is no ``__init__.py`` file!

In order for modules to be detected as plugin, they must follow the following
rules:

* Have a no-arg function ``create`` returning a instance of the class (or
  subclass) of :py:class:`puresnmp.security.SecurityModel`.
* Contain a int-variable ``IDENTIFIER``. This variable should map to the
  security model identifiers as defined in the SNMPv3 standard. See
  https://www.iana.org/assignments/snmp-number-spaces/snmp-number-spaces.xhtml
  and :rfc:`3411`
"""
import importlib
from threading import Lock
from typing import Any, Awaitable, Callable, Dict, Generic, TypeVar

from typing_extensions import Protocol

from puresnmp.credentials import Credentials
from puresnmp.exc import InvalidSecurityModel
from puresnmp.util import iter_namespace

#: The type of an *unsecured* message inside of "puresnmp"
TPureSNMPType = TypeVar("TPureSNMPType", bound=Any)

#: The type of a *secured* message outside of "puresnmp"
TX690Type = TypeVar("TX690Type", bound=Any)

#: A lock to ensure the global plugin dict is not accessed by multiple threads
DISCOVERY_LOCK = Lock()


class TSecurityPlugin(Protocol):
    """
    Protocol for security plugins
    """

    # pylint: disable=too-few-public-methods

    def create(self) -> "SecurityModel[TPureSNMPType, TX690Type]":
        """
        Create a new instance of a security model
        """
        ...


#: Global registry of detected plugins
DISCOVERED_PLUGINS: Dict[int, TSecurityPlugin] = {}


class SecurityModel(Generic[TPureSNMPType, TX690Type]):
    """
    Each Security Model defines the applied protecion on SNMP PDUs
    """

    #: The "Local Configuration Datastore" (LCD). This contains contextual
    #: information which may be needed for some security models (as defined by
    #: the SNMPv3 architecture.)
    local_config: Dict[bytes, Dict[str, Any]]

    def __init__(self) -> None:
        self.local_config = {}

    def generate_request_message(
        self,
        message: TPureSNMPType,
        security_engine_id: bytes,
        credentials: Credentials,
    ) -> TX690Type:
        """
        Take a plain unprocessed message and applies security to the message
        as defined by the concrete security model.

        It returns the processed message including security modifications.
        Further processing is provided by the "message-processing-model" to
        prepare it for sending out to the network.

        The kind of processing applied to the message depends on the
        credential type.

        :param message: The original message
        :param security_engine_id: The engine-id of the receiving SNMP engine
        :param credentials: A credential object giving information on what
            kind of operations are needed on the message.
        """
        raise NotImplementedError(f"Not yet implemented in {self.__class__}")

    def process_incoming_message(
        self,
        message: TX690Type,
        credentials: Credentials,
    ) -> TPureSNMPType:
        """
        Takes a message which included potential security modifications (like
        encryption) and "undoes" these modifications in order to make the
        message usable again.

        Returns an unprocessed message.

        The kind of processing applied to the message depends on the
        credential type.

        :param message: The original message
        :param credentials: A credential object giving information on what
            kind of operations are needed on the message.
        """
        raise NotImplementedError(f"Not yet implemented in {self.__class__}")

    def set_engine_timing(
        self,
        engine_id: bytes,
        engine_boots: int,
        engine_time: int,
    ) -> None:
        """
        Update the security model with timing information of the remote-engine.

        The timing information is required by SNMPv3 to authenticat/encrypt
        messages.
        """
        raise NotImplementedError(f"Not yet implemented in {self.__class__}")

    async def send_discovery_message(
        self,
        transport_handler: Callable[[bytes], Awaitable[bytes]],
    ) -> Any:
        """
        Send a discovery message to the remote engine.

        :param handler: A callable that is responsible to send data to the
            remote engine. This callable should already be aware of how to
            connect. It takes the bytes to be sent to the remote and should
            return the response bytes without any processing.
        """
        raise NotImplementedError(f"Not yet implemented in {self.__class__}")


def discover_plugins() -> None:
    """
    Load all privacy plugins into a global cache
    """
    if DISCOVERED_PLUGINS:
        return

    import puresnmp.security

    for _, name, _ in iter_namespace(puresnmp.security):
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


def create(identifier: int) -> SecurityModel[TPureSNMPType, TX690Type]:
    """
    Return an instance of the given security module by identifier.

    This looks up the module by "IDENTIFIER" as specified in the given plugin.

    If no plugin with the given identifier is found, a *KeyError* is raised
    """
    with DISCOVERY_LOCK:
        discover_plugins()
    if identifier not in DISCOVERED_PLUGINS:
        import puresnmp.security

        raise InvalidSecurityModel(
            str(puresnmp.security.__name__),
            identifier,
            sorted(DISCOVERED_PLUGINS.keys()),
        )

    return DISCOVERED_PLUGINS[identifier].create()
