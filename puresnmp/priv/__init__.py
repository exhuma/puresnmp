"""
This module provides a plugin architecture for privacy (enryption) methods.

Each privacy plugin can be distributed as separate package by providing
modules inside the namespace-package "puresnmp.priv". Note that in order to
be a valid namespace-package, such a package *must not* have a
``__init__.py`` file!

Example folder-structure for a privacy plugin:

.. code-block:: text

    my-privacy-plugin/
     +- setup.py (or pyproject.toml)
     +- puresnmp/
         +- priv/
             +- mymodule.py
             +- myothermodule.py

Note that there is no ``__init__.py`` file!

In order for modules to be detected as plugin, they must follow the following
rules:

* Have a function ``encrypt_data`` implementing the
  :py:meth:`puresnmp.priv.TPriv.encrypt_data` protocol.
* Have a function ``decrypt_data`` implementing the
  :py:meth:`puresnmp.priv.TPriv.decrypt_data` protocol.
* Contain a string-variable ``IDENTIFIER``. This variable should be
  user-friends and is used to uniquely identify this privacy module.
* Contain a int-variable ``IANA_ID``. This variable should have a value from
  IANA registered privacy protocols and is used to avoid duplicate plugin
  registrations. See
  https://www.iana.org/assignments/snmp-number-spaces/snmp-number-spaces.xhtml
  and :rfc:`3411`
"""
import importlib
from threading import Lock
from typing import Dict, NamedTuple

from typing_extensions import Protocol

from puresnmp.adt import EncryptedMessage, PlainMessage
from puresnmp.util import iter_namespace


class EncryptionResult(NamedTuple):
    """
    Wrapper for encrypted data.
    """

    #: The encrypted content (usually a PDU)
    encrypted_data: bytes

    #: The value that will be inserted into the "privParams" field from the
    #: SNMP spec. This should contain any "local" data that is needed to
    #: decrypt the data (like a salt for example)
    priv_params: bytes


class TPriv(Protocol):
    """
    Protocol describing the en-/de-cryption API
    """

    def encrypt_data(
        self,
        localised_key: bytes,
        engine_id: bytes,
        engine_boots: int,
        engine_time: int,
        data: bytes,
    ) -> EncryptionResult:
        """
        Encrypts data from an SNMP PDU following the SNMPv3 spec.

        :param localised_key: The encryption key localised to the given
            engine-id
        :param engine_id: The ID of the recipient SNMP-engine
        :param engine_boots: Number of times the recipient engine has been
            restarted
        :param data: The data that needs to be encrypted
        :returns: The encrypted data together with the used salt
        """
        ...

    def decrypt_data(
        self,
        localised_key: bytes,
        engine_id: bytes,
        engine_boots: int,
        engine_time: int,
        salt: bytes,
        data: bytes,
    ) -> bytes:
        """
        Decrypts a message

        :param localised_key: The decryption key localised to the given
            engine-id
        :param engine_id: The remote engine-id
        :param engine_boots: The number of engine-boots
        :param engine_time: Timeliness parameter for encryption
        :param salt: The salt used during encryption
        :param data: The encrypted SNMP message
        :returns: The unencrypted data.
        """
        ...


#: Global registry of detected plugins
DISCOVERED_PLUGINS: Dict[str, TPriv] = {}

#: Global registry of detected plugins by IANA ID
IANA_IDS: Dict[int, TPriv] = {}

DISCOVERY_LOCK = Lock()


def discover_plugins() -> None:
    """
    Load all privacy plugins into a global cache
    """
    if DISCOVERED_PLUGINS:
        return
    import puresnmp.priv

    for _, name, _ in iter_namespace(puresnmp.priv):
        mod = importlib.import_module(name)
        if not all(
            [
                hasattr(mod, "encrypt_data"),
                hasattr(mod, "decrypt_data"),
                hasattr(mod, "IDENTIFIER"),
                hasattr(mod, "IANA_ID"),
            ]
        ):
            continue
        if mod.IDENTIFIER in DISCOVERED_PLUGINS:  # type: ignore
            raise ImportError(
                "Plugin %r causes a name-clash with the identifier %r. "
                "This is already used by %r"
                % (mod, mod.IDENTIFIER, DISCOVERED_PLUGINS[mod.IDENTIFIER])  # type: ignore
            )
        if mod.IANA_ID in IANA_IDS:  # type: ignore
            raise ImportError(
                "Plugin %r uses a IANA ID (%d) which "
                "is already registered by %r"
                % (mod, mod.IANA_ID, IANA_IDS[mod.IANA_ID])  # type: ignore
            )
        DISCOVERED_PLUGINS[mod.IDENTIFIER] = mod  # type: ignore
        IANA_IDS[mod.IANA_ID] = mod  # type: ignore


def create(name: str) -> TPriv:
    """
    Return an instance of the given privacy module by identifier.

    This looks up the module by "IDENTIFIER" as specified in the given plugin.

    If no plugin with the given identifier is found, a *KeyError* is raised
    """

    with DISCOVERY_LOCK:
        discover_plugins()
    if name not in DISCOVERED_PLUGINS:
        import puresnmp.priv

        raise MissingPlugin(
            str(puresnmp.priv.__name__), name, sorted(DISCOVERED_PLUGINS.keys())
        )
    return DISCOVERED_PLUGINS[name]
