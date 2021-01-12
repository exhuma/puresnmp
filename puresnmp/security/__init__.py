import importlib
import pkgutil
from typing import Any, Dict

from typing_extensions import Protocol

import puresnmp.security
from puresnmp.adt import Message
from puresnmp.credentials import Credentials
from puresnmp.exc import InvalidSecurityModel


class TSecurityPlugin(Protocol):
    def create(self) -> "SecurityModel":
        ...


#: Global registry of detected plugins
DISCOVERED_PLUGINS: Dict[int, TSecurityPlugin] = {}


class SecurityModel:
    """
    Each Security Model defines the applied protecion on SNMP PDUs
    """

    IDENTIFIER: int

    #: The "Local Configuration Datastor" (LCD)
    local_config: Dict[bytes, Dict[str, Any]]

    #: A default local security config for unknown engine IDs
    default_auth: Dict[bytes, Dict[str, Any]]

    def __init__(self) -> None:
        self.local_config = {}
        self.default_auth = {}

    def set_default_auth(self, auth: Dict[bytes, Dict[str, Any]]) -> None:
        self.default_auth = auth

    def generate_request_message(
        self,
        message: Message,
        security_engine_id: bytes,
        credentials: Credentials,
    ) -> Message:
        raise NotImplementedError("Not yet implemented")

    def process_incoming_message(self, message: Message) -> Message:
        raise NotImplementedError("Not yet implemented")


def iter_namespace(ns_pkg):
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")


def discover_plugins():
    for _, name, _ in iter_namespace(puresnmp.security):
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


def create(identifier: int) -> SecurityModel:

    if not DISCOVERED_PLUGINS:
        discover_plugins()
    if identifier not in DISCOVERED_PLUGINS:
        raise InvalidSecurityModel(identifier)

    return DISCOVERED_PLUGINS[identifier].create()
