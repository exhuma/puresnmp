.. _cookbook:

Cookbook
========

.. note:: Note on Types

    In the current version, some types internal to SNMP and :term:`X.690` are
    abstracted away. But not all of them yet (see :ref:`type_tree`). One goal
    of the library is to act as a border between pure Python code and SNMP
    internals. It is not always possible to hide the type information.
    Especially on ``SET`` requests.

    "Hiding" these types while still retaining access to them if needed, is a
    work in progress!

    Additionally, not *all* core types are yet supported. In this case a
    ``NonASN1Type`` will be returned. This instance contains the type
    information byte and the raw bytes value.


"Raw" vs. "Pythonic" API
------------------------

Apart from the functions in the :py:mod:`puresnmp` package, the library
provides two additional entry points:

* :py:mod:`puresnmp.api.pythonic` (same as :py:mod:`puresnmp`)
* :py:mod:`puresnmp.api.raw`

Both modules provide essentially the same functions, with the difference that
the returned values will be instances of :py:class:`puresnmp.x690.types.Type`
for the "raw" interfaces, and pure Python data-types for the "pythonic"
interface. Example::

    from puresnmp import get
    from puresnmp.api.raw import get as raw_get

    ip = ...
    community = ...
    oid = '1.3.6.1.2.1.3.1.1.3.0.1.192.168.168.1'  # only an example

    result = get(ip, community, oid)
    raw_result = raw_get(ip, community, oid)

    print(type(result), repr(result))
    # Output: <class 'ipaddress.IPv4Address'> IPv4Address('192.168.168.1')

    print(type(raw_result), repr(raw_result))
    # Output: <class 'puresnmp.types.IpAddress'> IpAddress(b'\xc0\xa8\xa8\x01')

The reason is to provide a non-leaky abstraction by default which should make
most use-cases very easy to work with and future updates to the library more
robust and easier to upgrade for users.

The downside is that there is a slight overhead due to type conversions, and
some interesting information may be lost. These downsides can be remedies by
using the "raw" interface.

It is up to the end-user to decide which API is more appropriate for the task
at hand. In *general* using the "pythonic" interface should be preferred.

.. toctree::
   :maxdepth: 1
   :glob:

   *
