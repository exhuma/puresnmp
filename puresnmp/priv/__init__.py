"""
This module provides a plugin architecture for privacy (enryption) methods.

Each privacy plugin can be distributed as separate package by providing
modules inside the namespace-package "puresnmp.priv". Note that in order to
be a valid namespace-package, such a package *must not* have a
``__init__.py`` file!

Example folder-structure for a privacy plugin::

    my-privacy-plugin/
     +- setup.py (or pyproject.toml)
     +- puresnmp/
         +- priv/
             +- mymodule.py
             +- myothermodule.py

Note that there is no ``__init__.py`` file!

In order for modules to be detected as privacy plugin, they must follow the
following rules:

* Have a function ``encrypt_data`` implementing the
  :py:meth:`puresnmp.priv.TPriv.encrypt_data` protocol.
* Have a function ``decrypt_data`` implementing the
  :py:meth:`puresnmp.priv.TPriv.decrypt_data` protocol.
* Contain a string-variable ``IDENTIFIER``. This variable is used to uniquely
  identify this privacy module.
"""
import importlib
import pkgutil
from types import ModuleType
from typing import Dict, Generator, NamedTuple

from typing_extensions import Protocol

from puresnmp.adt import EncryptedMessage, PlainMessage


class EncryptionResult(NamedTuple):
    """
    Wrapper for encrypted data.

    Each encryption result has its own "salt" which is needed for decryption.
    """

    encrypted_data: bytes
    salt: bytes


class TPriv(Protocol):
    """
    Protocol describing the en-/de-cryption API
    """

    def encrypt_data(
        self, key: bytes, engine_id: bytes, engine_boots: int, data: bytes
    ) -> EncryptionResult:
        """
        Encrypts data from an SNMP PDU following the SNMPv3 spec.

        :param key: The encryption key
        :param engine_id: The ID of the recipient SNMP-engine
        :param engine_boots: Number of times the recipient engine has been
            restarted
        :param data: The data that needs to be encrypted
        :returns: The encrypted data together with the used salt
        """
        ...

    def decrypt_data(
        self, decrypt_key: bytes, message: EncryptedMessage
    ) -> PlainMessage:
        """
        Decrypts a message

        :param decrypt_key: The key used for decryption
        :param message: The encrypted SNMP message
        :returns: The unencrypted message.
        """
        ...


#: Global registry of detected plugins
DISCOVERED_PLUGINS: Dict[str, TPriv] = {}


def iter_namespace(
    ns_pkg: ModuleType,
) -> Generator[pkgutil.ModuleInfo, None, None]:
    """
    Iterates over modules inside the given namespace
    """
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")  # type: ignore


def discover_plugins():
    """
    Load all privacy plugins into a global cache
    """
    plugin_container = importlib.import_module("puresnmp.priv")

    for _, name, _ in iter_namespace(plugin_container):
        mod = importlib.import_module(name)
        if not all(
            [
                hasattr(mod, "encrypt_data"),
                hasattr(mod, "decrypt_data"),
                hasattr(mod, "IDENTIFIER"),
            ]
        ):
            continue
        if mod.IDENTIFIER in DISCOVERED_PLUGINS:
            raise ImportError(
                "Plugin %r causes a name-clash with the identifier %r. "
                "This is already used by %r"
                % (mod, mod.IDENTIFIER, DISCOVERED_PLUGINS[mod.IDENTIFIER])
            )
        DISCOVERED_PLUGINS[mod.IDENTIFIER] = mod


def create(name: str) -> TPriv:
    """
    Return an instance of the given privacy module by identifier.

    This looks up the module by "IDENTIFIER" as specified in the given plugin.

    If no plugin with the given identifier is found, a *KeyError* is raised
    """

    if not DISCOVERED_PLUGINS:
        discover_plugins()
    return DISCOVERED_PLUGINS[name]
