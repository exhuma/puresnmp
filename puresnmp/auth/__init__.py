import importlib
import pkgutil

from typing_extensions import Protocol

import puresnmp.auth
from puresnmp.adt import Message

#: Global registry of detected plugins
DISCOVERED_PLUGINS = {}


class TAuth(Protocol):
    def authenticate_outgoing_message(
        self, auth_key: bytes, data: bytes, engine_id: bytes
    ) -> bytes:
        ...

    def authenticate_incoming_message(
        self,
        auth_key: bytes,
        data: bytes,
        received_digst: bytes,
        engine_id: bytes,
    ) -> None:
        ...


def iter_namespace(ns_pkg):
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")


def discover_plugins():
    for _, name, _ in iter_namespace(puresnmp.auth):
        mod = importlib.import_module(name)
        if not all(
            [
                hasattr(mod, "authenticate_incoming_message"),
                hasattr(mod, "authenticate_outgoing_message"),
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


def create(name: str) -> TAuth:

    if not DISCOVERED_PLUGINS:
        discover_plugins()
    return DISCOVERED_PLUGINS[name]
