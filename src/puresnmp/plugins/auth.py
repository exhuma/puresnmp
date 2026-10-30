"""
This module provides a plugin architecture for authentication methods.

Each authentication plugin can be distributed as separate package by providing
modules inside the namespace-package ``puresnmp_plugins.auth``. Note that in
order to be a valid namespace-package, such a package *must not* have a
``__init__.py`` file!

Example folder-structure for a privacy plugin:

.. code-block:: text

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
  :py:meth:`puresnmp_plugins.auth.TAuth.authenticate_outgoing_message`
  protocol.
* Have a function ``authenticate_incoming_message`` implementing the
  :py:meth:`puresnmp_plugins.auth.TAuth.authenticate_incoming_message`
  protocol.
* Contain a string-variable ``IDENTIFIER``. This variable should be
  user-friendly and is used to uniquely identify this authentication module.
* Contain a int-variable ``IANA_ID``. This variable should have a value from
  IANA registered authentication protocols and is used to avoid duplicate plugin
  registrations. See
  https://www.iana.org/assignments/snmp-number-spaces/snmp-number-spaces.xhtml
  and :rfc:`3411`

Optionally, a module may contain an int-variable ``DIGEST_LENGTH`` with the
number of octets of the digest it puts into the authentication parameters of
a message. It defaults to 12, the length used by the :rfc:`3414` protocols.
Protocols with a different digest length, like the HMAC-SHA-2 protocols of
:rfc:`7860`, must set it.
"""

import importlib
from threading import Lock
from types import ModuleType
from typing import Dict, Protocol


from puresnmp.exc import MissingPlugin, UnknownAuthModel, UnknownPrivacyModel
from puresnmp.plugins.pluginbase import Loader
from puresnmp.util import iter_namespace


class TAuth(Protocol):
    """
    Protocol describing the authentication API
    """

    def authenticate_outgoing_message(
        self, auth_key: bytes, data: bytes, engine_id: bytes
    ) -> bytes:  # pragma: no cover
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
        received_digest: bytes,
        engine_id: bytes,
    ) -> bool:  # pragma: no cover
        """
        Determine whether a message is authentic.

        This will take the raw bytes of an incoming message and derive a
        digest based on the authentication key and the receipient engine ID.
        The digest is compared to an expected digest. If they differ, this
        function will return False.
        """
        ...


#: The digest length of plugins which do not define ``DIGEST_LENGTH``
DEFAULT_DIGEST_LENGTH = 12


def digest_length(plugin: TAuth) -> int:
    """
    Return the number of octets of the digest created by *plugin*.

    :param plugin: An authentication plugin as returned by :py:func:`create`
    :returns: The plugin's ``DIGEST_LENGTH``, or
        :py:data:`DEFAULT_DIGEST_LENGTH` if it does not define one
    """
    return int(getattr(plugin, "DIGEST_LENGTH", DEFAULT_DIGEST_LENGTH))


def is_valid_auth_mod(mod: ModuleType) -> bool:
    return all(
        [
            hasattr(mod, "authenticate_incoming_message"),
            hasattr(mod, "authenticate_outgoing_message"),
            hasattr(mod, "IDENTIFIER"),
            hasattr(mod, "IANA_ID"),
        ]
    )


def create(identifier: str) -> TAuth:
    """
    Return an instance of the given authentication module by identifier.

    This looks up the module by "IDENTIFIER" as specified in the given plugin.

    :param name: The identifier of the module
    :raises puresnmp.exc.MissingPlugin: If no module with the given name is
        found
    """
    namespace = "puresnmp_plugins.auth"
    loader = Loader(namespace, is_valid_auth_mod)
    result = loader.create(identifier)
    if not result:
        raise UnknownAuthModel(
            namespace,
            identifier,
            sorted(loader.discovered_plugins.keys()),
        )
    return result  # type: ignore
