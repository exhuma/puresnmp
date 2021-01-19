"""
This module provides a plugin architecture for authentication methods.

Each authentication plugin can be distributed as separate package by providing
modules inside the namespace-package "puresnmp.auth". Note that in order
to be a valid namespace-package, such a package *must not* have a
``__init__.py`` file!

Example folder-structure for a privacy plugin::

    my-auth-plugin/
     +- setup.py (or pyproject.toml)
     +- puresnmp/
         +- auth/
             +- mymodule.py
             +- myothermodule.py

Note that there is no ``__init__.py`` file!

In order for modules to be detected as plugin, they must follow the following
rules:

* Have a function ``authenticate_outgoing_message`` implementing the
  :py:meth:`puresnmp.auth.TAuth.authenticate_outgoing_message` protocol.
* Have a function ``authenticate_incoming_message`` implementing the
  :py:meth:`puresnmp.auth.TAuth.authenticate_incoming_message` protocol.
* Contain a string-variable ``IDENTIFIER``. This variable should be
  user-friends and is used to uniquely identify this authentication module.
* Contain a int-variable ``IANA_ID``. This variable should have a value from
  IANA registered authentication protocols and is used to avoid duplicate plugin
  registrations. See
  https://www.iana.org/assignments/snmp-number-spaces/snmp-number-spaces.xhtml
  and :rfc:`3411`
"""
import importlib
from typing import Dict

from typing_extensions import Protocol

from puresnmp.util import iter_namespace


class TAuth(Protocol):
    """
    Protocol describing the authentication API
    """

    def authenticate_outgoing_message(
        self, auth_key: bytes, data: bytes, engine_id: bytes
    ) -> bytes:
        """
        Calculate a digest for an outgoing message

        This will take the raw bytes of an outgoing message and derive a
        digest based on the authentication key and the receipient engine ID
        """
        ...

    def authenticate_incoming_message(
        self,
        auth_key: bytes,
        data: bytes,
        received_digst: bytes,
        engine_id: bytes,
    ) -> None:
        """
        Calculate a digest for an incoming message. Raise an exception on error.

        This will take the raw bytes of an incoming message and derive a
        digest based on the authentication key and the receipient engine ID.
        The digest is compared to an expected digest. If they differ, this
        function will raise an exception.
        """
        ...


#: Global registry of detected plugins
DISCOVERED_PLUGINS: Dict[str, TAuth] = {}
#: Global registry of detected plugins by IANA ID
IANA_IDS: Dict[int, TAuth] = {}


def discover_plugins():
    """
    Load all privacy plugins into a global cache
    """
    namespace = importlib.import_module("puresnmp.auth")
    for _, name, _ in iter_namespace(namespace):
        mod = importlib.import_module(name)
        if not all(
            [
                hasattr(mod, "authenticate_incoming_message"),
                hasattr(mod, "authenticate_outgoing_message"),
                hasattr(mod, "IDENTIFIER"),
                hasattr(mod, "IANA_ID"),
            ]
        ):
            continue
        if mod.IDENTIFIER in DISCOVERED_PLUGINS:
            raise ImportError(
                "Plugin %r causes a name-clash with the identifier %r. "
                "This is already used by %r"
                % (mod, mod.IDENTIFIER, DISCOVERED_PLUGINS[mod.IDENTIFIER])
            )
        if mod.IANA_ID in IANA_IDS:
            raise ImportError(
                "Plugin %r uses a IANA ID (%d) which "
                "is already registered by %r"
                % (mod, mod.IANA_ID, IANA_IDS[mod.IANA_ID])
            )
        DISCOVERED_PLUGINS[mod.IDENTIFIER] = mod
        IANA_IDS[mod.IANA_ID] = mod


def create(name: str) -> TAuth:
    """
    Return an instance of the given authentication module by identifier.

    This looks up the module by "IDENTIFIER" as specified in the given plugin.

    If no plugin with the given identifier is found, a *KeyError* is raised
    """

    if not DISCOVERED_PLUGINS:
        discover_plugins()
    return DISCOVERED_PLUGINS[name]
