puresnmp
========

.. note::

   *puresnmp v2.x* is a major update from *puresnmp v1.x*. See
   :ref:`upgrading` for information of the key changes.

   The v1.x branch is now in "maintenance only" mode and will only receive
   critical fixes.

Basic Example
-------------

This basic example executes an SNMP GET request. The details are explained
below.

.. code-block:: python

   import asyncio
   from puresnmp import Client, V2C, PyWrapper

   async def example():
      client = PyWrapper(Client("192.0.2.1", V2C("public")))
      output = await client.get("1.3.6.1.2.1.1.1.0")
      return output

   print(asyncio.run(example()))

The above will execute a community-based SNMPv2 GET request on the device
with IP ``192.0.2.1`` and read the value on OID ``1.3.6.1.2.1.1.1.0``. The
output will be for example::

   b'Linux 2e9eccbc4529 4.15.0-115-generic #116-Ubuntu SMP Wed Aug 26 14:04:49 UTC 2020 x86_64'

More Requests
-------------

Want to do more than just a "GET" request? Have a look at
:py:class:`~puresnmp.api.pythonic.PyWrapper`.

Dissection
----------

.. code-block:: python

   Client("192.0.2.1", V2C("public"))

This creates a new "leaky" client to the device at IP "192.0.2.1". Is is
"leaky" because method arguments and return-values use SNMP-specific like
:py:class:`puresnmp.types.Counter` or :py:class:`x690.types.OctetString`.

It is already usable as-is but can be improved by wrapping it with
:py:class:`~puresnmp.api.pythonic.PyWrapper`.

.. code-block:: python

    client = PyWrapper(...)

This wrapper exposes the same methods as the internal client but converts
input- and output-values from/to native (pure) Python types. This abstracts
SNMP internals and makes client code much more pythonic. It also decouples
client-code from internal changes and should make client code more robust and
independent.

.. note::

   **Caveat**

   When executing "SNMP SET" requests, the SNMP specific data-types need to
   be known. So "SET" commands will inherently always be leaky.

.. toctree::
   :maxdepth: 2
   :caption: Contents

   design
   plugins
   upgrading
   changelog
   API Docs <api/modules>
   Plugins API <plugins_api/modules>




Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
