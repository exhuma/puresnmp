Design Decisions
================

Another SNMP package?
---------------------

There are at least 3 more SNMP packages out there. Those are:

* snimpy_
* pysnmp_
* net-snmp_

.. _snimpy: https://pypi.org/project/snimpy/
.. _pysnmp: https://pypi.org/project/pysnmp/
.. _net-snmp: http://net-snmp.sourceforge.net/

So why another package? **API simplicity, Maintainability & MIB independence**

The existing libraries all suffer from an overall complexity to use in simple
applications. This complexity is partially dictated by the SNMP RFCs like
:rfc:`3411`. The focus on usage simplicity has driven many of the following
design decisions.

While usage simplicity is one thing, maintainability is another. For that,
see the point about RFC-divergence below.

Finally, all *existing* modules have a strong focus on MIBs, which can be
problematic at times. Especially for heterogenuous networks. :py:mod:`puresnmp`
makes it easy to work *without* MIBs.

Extensive Documentation
-----------------------

Simple and useful documentation is an additional focus of this library. The
documentation provides a lot of example-code which should make usage of the
library a lot easier. The examples in the documentation are covered by
doctests wherever possible. This forces the examples in the docstrings to be
*complete* and should be fairly copy/pasteable.

Most of these examples are located in :py:class:`puresnmp.api.raw.Client`
(aliased for convenience as :py:class:`puresnmp.Client`)

.. note::

    When using the documentation examples from
    :py:class:`puresnmp.api.raw.Client` also consider using
    :py:class:`puresnmp.api.pythonic.PyWrapper` (aliased as
    :py:class:`puresnmp.PyWrapper`) to decouple internal data-types from your
    application.


Simple Data-Types
-----------------

Using :py:class:`puresnmp.api.pythonic.PyWrapper` all data-types are
converted at the seam between the internal Python world and the SNMP worls
(with the exception of "SET" requests).

Applications using the :py:class:`~puresnmp.api.pythonic.PyWrapper` will be
strongly decoupled from any internal changes inside :py:mod:`puresnmp`.

All *internal* datatypes inherit from :py:class:`x690.types.X690Type` and
provide the :py:attr:`~x690.types.X690Type.value` property to retrieve the
pure-Python value.

This may hide details from the exchanged data-types with the remote SNMP
device. For example, both :py:class:`~x690.types.Counter` and
:py:class:`~x690.types.Integer` are converted to pure-Python integers. For most
use-cases this is useful and convenient. But if needed, they can always be
accessed by using :py:attr:`puresnmp.api.pythonic.PyWrapper.client`.


No MIB Support?
---------------

Experience has shown that MIB modules can be very fragile, especially on very
heterogenuous networks. Raw OIDs are much more stable and reliable, at the
expense of "human-readility".

``puresnmp`` skips the processing of MIBs for this reason. Adding MIB support
is still possible as "wrapper" around the lower level primitives, but at the
moment there are no plans for development of this. Note that the library is
currently actively used on a large network with over 6k devices of various
manufacturers. All without MIBs, all without problems.

Effectively, MIBs sit between the user and the SNMP protocol.
:py:mod:`puresnmp` provides low-level support for SNMP.

Not having native support for MIBs might seem very limiting at first. Let's
look at the benefits of MIBs:

* They provide additional data-types (which are always sub-types of
  native/vanilla SNMP types)
* They provide definitions for "tables"
* They provide human-readable names for OIDs

All data-types used by ``puresnmp`` are compatible with the data-types
defined in MIBs. Some more esoteric data-types may be reported as
:py:class:`x690.types.OctetString` without MIBs, but they always represent
the real value.

Low-level table support is provided by
:py:meth:`puresnmp.api.pythonic.PyWrapper.table` and
:py:meth:`puresnmp.api.raw.Client.table` but row-indeces may need to be
post-processed.

Converting OIDs to/from human-readable text should primarily be done on the
UI level. This is not the responsibility of the library.


Divergence from RFC-3411
------------------------

:rfc:`3411` dictates an overall architecture which is very generic. That
architecture is "open" enough to allow it being implemented in many
programming languages. Dynamic languages like Python allow for different
implementations which would suffer from strict adherence to the RFC.

The RFC has one clear aim: Being future-proof by "pluggability".

This pluggability is provided in :py:mod:`puresnmp` by the use of "namespace
modules". This allows us to provide new functionality in the future without
sacrificing "pythonic" code. It does therefore slightly diverge from the
RFC-3411 process of how "plugins" are looked up.

Finally, the library has a primary focus on being an SNMP *client*. Not an
SNMP *server*. For this reason, a lot of implementations from the RFC have
been skipped.

Like MIB support, adding support to respond to SNMP requests is not out of
the question, but not planned either. Feel free to contact the author(s) if
you want to provide support for this.


Type Hinting
------------

The library is fully type-hinted providing a stable and maintainable code-base.


Async first
-----------

The library *only* provides async functions. This allows us to have one
common code-base for everything. The previous version (v1.x) of puresnmp
contained both a "sync" and "async" implementation, making maintainance
cumbersome and error-prone.

``puresnmp`` can be easily integrated into a non-async application by using
:py:func:`asyncio.run`.
