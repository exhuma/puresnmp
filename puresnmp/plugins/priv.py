"""
This module provides a plugin architecture for privacy (enryption) methods.

Each privacy plugin can be distributed as separate package by providing
modules inside the namespace-package "puresnmp_plugins.priv". Note that in
order to be a valid namespace-package, such a package *must not* have a
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
  :py:meth:`puresnmp_plugins.priv.TPriv.encrypt_data` protocol.
* Have a function ``decrypt_data`` implementing the
  :py:meth:`puresnmp_plugins.priv.TPriv.decrypt_data` protocol.
* Contain a string-variable ``IDENTIFIER``. This variable should be
  user-friends and is used to uniquely identify this privacy module.
"""
from types import ModuleType
from typing import NamedTuple

from typing_extensions import Protocol

from puresnmp.exc import UnknownPrivacyModel
from puresnmp.plugins.pluginbase import Loader


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
    ) -> EncryptionResult:  # pragma: no cover
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
    ) -> bytes:  # pragma: no cover
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


def is_valid_priv_mod(mod: ModuleType) -> bool:
    return all(
        [
            hasattr(mod, "encrypt_data"),
            hasattr(mod, "decrypt_data"),
            hasattr(mod, "IDENTIFIER"),
            hasattr(mod, "IANA_ID"),
        ]
    )


def create(identifier: str) -> TPriv:
    namespace = "puresnmp_plugins.priv"
    loader = Loader(namespace, is_valid_priv_mod)
    result = loader.create(identifier)
    if not result:
        raise UnknownPrivacyModel(
            namespace,
            identifier,
            sorted(loader.discovered_plugins.keys()),
        )
    return result  # type: ignore
