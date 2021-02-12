.. _upgrading:

Upgrading from v1.x to v2.x
===========================


AsyncIO first
-------------

The "sync" implementation has been removed in favour of code-deduplication.
All exposed methods are now asyncio coroutines.

Reasons for Change
~~~~~~~~~~~~~~~~~~

``puresnmp`` v1.x had a lot of code duplication by providing both a "sync" and
"async" implementation. This made it error-prone to add new features and
applying bugfixes.

Providing a single code-base made the maintenance easier at the cost of
losing the "sync" implementation.

Mitigation: calling a "sync" corouting can be done fairly easily by wrapping
the call in either :py:func:`asyncio.run` (Python 3.8+) or
:py:func:`asyncio.loop.run_until_complete` (Python <3.8).

.. note::

    Care has to be taken when running this multi-threaded. The asyncio
    "event-loop" is global in Python. This should not be an issue in most
    cases. If strange things happen, read up on `asyncio with multi-threading`_.

.. _asyncio with multi-threading: https://docs.python.org/3/library/asyncio-dev.html#concurrency-and-multithreading

Example
~~~~~~~

.. code-block:: python
    :caption: Running in "async" context

    import asyncio
    import puresnmp

    async def hello_world():
        client = puresnmp.PyWrapper(
            puresnmp.Client("192.0.2.1", puresnmp.V2C("private))
        )
        result = await client.get("1.3.6.1.2.1.1.2.0)
        return result

.. code-block:: python
    :caption: Running in "sync" context, Python 3.8+

    import asyncio
    import puresnmp

    client = puresnmp.PyWrapper(
        puresnmp.Client("192.0.2.1", puresnmp.V2C("private))
    )
    coro = client.get("1.3.6.1.2.1.1.2.0)
    asyncio.run(coro)

.. code-block:: python
    :caption: Running in "sync" context, Python <3.8

    import asyncio
    import puresnmp

    client = puresnmp.PyWrapper(
        puresnmp.Client("192.0.2.1", puresnmp.V2C("private))
    )
    loop = asyncio.get_event_loop()
    coro = client.get("1.3.6.1.2.1.1.2.0)
    loop.run_until_complete(coro)


Module-Level functions moved to client-classes
----------------------------------------------

``puresnmp`` v1.x has four core modules which provided simple functions to
execute SNMP requests: ``puresnmp.api.raw`` and ``puresnmp.api.pythonic``.
And *asyncio* equivalents of both.

``puresnmp`` now has *one* core code-base in
:py:class:`puresnmp.api.raw.Client`. And a wrapper dealing with data-type
conversion in :py:class:`puresnmp.api.pythonic.PyWrapper`.

Reasons for Change
~~~~~~~~~~~~~~~~~~

* Provides the ability to deduplicate certain values (IP-address, credentials,
  UDP timeout, ...) in client code.
* No longer polluting the global (builtin) namespace.

Example
~~~~~~~

.. code-block:: python
    :caption: puresnmp v1.x

    from puresnmp import get

    result = get("192.0.2.1", "private", "1.3.6.1.2.1.1.2.0")
    result = get("192.0.2.1", "private", "1.3.6.1.2.1.1.1.0")

.. code-block:: python
    :caption: puresnmp v2.x

    from puresnmp import Client, PyWrapper, V2C

    client = PyWrapper(Client("192.0.2.1", V2C("private")))
    result = await client.get("1.3.6.1.2.1.1.2.0")
    result = await client.get("1.3.6.1.2.1.1.1.0")


Strict Data-Type Decoupling
---------------------------

The old "pythonic" interface has been replaced with a "wrapper" class. This
class wraps a normal "raw" client and takes care of data-type conversions.
The goal of the wrapper is to shield any client-code from changes to internal
data-types.


Reasons for Change
~~~~~~~~~~~~~~~~~~

``puresnmp`` v1.x had a leaky abstraction through inconsistent internal
handling of SNMP "VarBinds". They sometimes contained instances of
``ObjectIdentifier`` and :py:class:`x690.types.Type` classes and sometimes
pure-Python data-types. It also caused an overall inconsistency between the
"raw" and "pythonic" interfaces.

This made the usage of ``puresnmp`` potentially brittle as internal changes
could break client-code. Extra care was taken to avoid this throught the
history of ``puresnmp``. This blocked some internal changes.

The data-types are now fully decoupled via the
:py:class:`puresnmp.api.pythonic.PyWrapper` class. This decoupling is
"opt-in" from the client code and it is possible to use
:py:class:`puresnmp.api.raw.Client` without wrapper. By exposing internal
data-types :py:class:`~puresnmp.api.raw.Client` instances offer more
flexibility at the expense of additional risk that internal changes break
client code.


Example
~~~~~~~

.. code-block:: python
    :caption: "raw" api

    from puresnmp import Client, ObjectIdentifier, V2C

    client = Client("192.0.2.1", V2C("private"))
    result = await client.get(ObjectIdentifier("1.3.6.1.2.1.1.2.0"))
    print(repr(result))
    # output: OctetString(b"...")

.. code-block:: python
    :caption: Using "PyWrapper"

    from puresnmp import Client, ObjectIdentifier, V2C, PyWrapper

    client = PyWrapper(Client("192.0.2.1", V2C("private")))
    result = await client.get("1.3.6.1.2.1.1.2.0")
    print(repr(result))
    # output: b"..."


ObjectIdentifier Data-Type
--------------------------

The data-type of :py:class:`x690.types.ObjectIdentifier` is now
consistently exposing "str" instances.

Reasons for Change
~~~~~~~~~~~~~~~~~~

* Simplification of client code (no longer necessary to use
  ``.from_string(...)``)
* More user-friendly "repr" output

Example
~~~~~~~

.. code-block:: python
    :caption: puresnmp v1.x

    from x690.types import ObjectIdentifier as OID

    oid = OID.from_string("1.3.6.1.2.1.1.2.0")
    print(repr(oid))
    # output: ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 2, 0))

.. code-block:: python
    :caption: puresnmp v2.x

    from x690.types import ObjectIdentifier as OID

    oid = OID("1.3.6.1.2.1.1.2.0")
    print(repr(oid))
    # output: ObjectIdentifier("1.3.6.1.2.1.1.2.0")
