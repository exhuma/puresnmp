puresnmp
========

.. note::

   *puresnmp v2.x* is a major update from *puresnmp v1.x*. See
   :ref:`upgrading` for information of the key changes.

   The v1.x branch is now in "maintenance only" mode and will only receive
   critical fixes.

Let's start with a simple quickstart and go into design-decisions,
class-descriptions and details a bit later.

.. code-block:: python

   import asyncio
   from puresnmp import Client, V2C, PyWrapper

   async def example():
      client = PyWrapper(Client("192.0.2.1", V2C("public")))
      output = await client.get("1.3.6.1.2.1.1.1.0")
      return output

   loop = asyncio.get_event_loop()
   print(loop.run_until_complete(example()))

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

This creates a new "leaky" client to the device at IP "192.0.2.1". This
client is "leaky" in the sense that it leaks internal data-types as method
arguments and return-values. It is already usable as-is and
:py:class:`~puresnmp.api.pythonic.PyWrapper` is not strictly needed, but read
on.

.. code-block:: python

    client = PyWrapper(...)

This wraps the "leaky" client by converting all function arguments from
native Python data-types to internal data types. Return values are also
converted from internal to "native-python". This decouples client-code from
internal changes and should make client code more robust and independent.

.. note::

   **Caveat**

   When executing "SNMP SET" requests, the SNMP specific data-types need to
   be known. So "SET" commands will inherently always be leaky.

Finally, let's execute an SNMP-Get request on the given OID and get the value.

.. code-block:: python

   output = await client.get(...)

.. toctree::
   :maxdepth: 2
   :caption: Contents

   design
   plugins
   upgrading
   changelog
   API Docs <api/modules>




Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
