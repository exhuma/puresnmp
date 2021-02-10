Plugins
=======

:rfc:`3411` provides an extensible architecture by providing a mechanism to
support different "message processings models", "security models",
"authentication models" and "privary models". These 4 extension points are
provided as *native* `namespace packages`_ in ``puresnmp``.

There are other pluggable "seams" in :rfc:`3411` but they are currently not
exposed as they are rather obscure. They can be exposed in the future if
requested/required.

.. _namespace packages: https://packaging.python.org/guides/packaging-namespace-packages/#native-namespace-packages

Message Processing Models
-------------------------

Messages processing models (or MPM for short) define how an SNMP message is
structured. It is the responsibility of an MPM to transform a user request to
bytes that can be sent to the remote SNMP device. An MPM also has the
responsibility to make use of any authentication//privacy/security module if
needed.

Security
--------

Security plugins are responsible to ensure that the user defined by the
"credentials" object has the permissions to access given OIDs. Security
plugins may also hand over processing to "authentication" and/or "privacy"
modules.

The security model is defined by an identifier in the SNMPv3 message header.
Additional arguments for the security model are encoded in the
``security_parameters`` fiels of the message header.

Authentication
--------------

Authentication plugins have the responsibility to ensure that a message was
created by/for an entity with given credentials. For example, in SNMPv3, the
MD5 and SHA1 authentication modules use the authentication parameter of the
credentials as secret key which is used together with a packet payload to
generate a message authentication code.

Privacy
-------

Privacy modules have the responsibility to obfuscate the message contents
from prying eyes. For example, in SNMPv3, the DES and AES plugins use the
"priv-parameters" in the credentials object as secret key to encrypt/decrypt
the message.

.. note::

    DES and AES support are provided by the third-party module
    :py:mod:`puresnmp-crypto`. Installation of that packet is sufficient to
    make it work. The package meta-data provide the ``crypto`` extra-flag to
    make installation easier.

    They are provided separately in case the library does not need DES/AES
    support, making the dependencies a bit lighter.


Providing new Plugins
---------------------

Plugin lookup works by comparing identifiers defined in the plugin module
with the value referenced in the SNMP message. If a match is found, the
``.create()`` function of the module is called to get a reference to the
plugin. The details of the identifiers and signature of the ``.create()``
function depends on plugin-type.

Refer to the builtin plugins as a template.

Privacy plugins are provided externally to keep the dependencies of
``puresnmp`` clean. Therefore, you have to look at `exhuma/puresnmp-crypto`_
for a "privacy" plugin template.

For packaging, you can also refer to `exhuma/puresnmp-crypto`_ as a template.

.. _exhuma/puresnmp-crypto: https://github.com/exhuma/puresnmp-crypto


Builtin Plugins
===============

.. toctree::

   :maxdepth: 2
   :caption: Builtin Plugins
   :glob:

   plugins_api/modules
