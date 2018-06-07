High-Level Overview
===================

Apart from that, the package is internally split into a few broad categories:

* :term:`X.690`
* SNMP
* Networking Code
* Type Registry


X.690
-----

See :py:mod:`puresnmp.x690`

This part of the package deals with the :term:`X.690` standard for byte
encodings (using BER in the case of SNMP). It is the place were most of the
marshalling/unmarshalling from/to bytes happens.


SNMP
----

SNMP build on top of :term:`X.690` and defines a couple of higher-level
concepts like "PDUs" (:py:class:`~puresnmp.pdu.GetRequest` and friends), and
adds more types (:py:class:`~puresnmp.types.IpAddress`, ...)


Talking to the Network
----------------------

All the networking code is centralised in one place:
:py:mod:`puresnmp.transport`. This module represents a very thin layer between
the application code and the physical network.

By being as thin as possible it's - hopefully - easy to swap this out, and it
definitely makes testing a lot easier.

The Registry
------------

All known types inherit directly or indirectly from
:py:class:`puresnmp.x690.types.Type`. By doing so, the classes get read into a
"registry" (found at :py:class:`puresnmp.x690.types.Registry`). This class
provides the mechanism to map :term:`X.690` type information (which is encoded
in the first bytes of a :term:`TLV` value) to Python classes. To properly
detect the types, the class *must* define two class-level variables:

``TAG``
    The actual type identifier.

``TYPECLASS``
    One of :py:const:`~puresnmp.x690.util.TypeInfo.UNIVERSAL`,
    :py:const:`~puresnmp.x690.util.TypeInfo.APPLICATION`,
    :py:const:`~puresnmp.x690.util.TypeInfo.CONTEXT`, or
    :py:const:`~puresnmp.x690.util.TypeInfo.PRIVATE`


.. note::

    :term:`X.690` makes the difference between the 4 major typeclasses and each
    typclass has its separate type identifiers (named "tags" in puresnmp). On
    the network these values are merged into one byte. So sniffing the network
    you will see ``b'\x30'`` for a "Sequence" type. But this value, what you
    see is actually the three values "UNIVERSAL" (``0x00``), "CONSTRUCTED"
    (``0x01``) and the tag for a sequence ``0x10`` all jumbled up into one
    byte!

    This makes debugging a bit iffy... The type information is documented in
    :term:`X.690` as ``0x10`` for a *Sequence* but you don't see this on the
    net!  ``0x10`` is also what's defined in
    :py:const:`puresnmp.x690.types.Sequence.TAG`!  This gives parity between
    the official documentation and the source-code.

    An early decision in *puresnmp* was to split this byte into three, exposing
    the contained values to the application code, but also meaning that what
    you sniff on the net is not what you see in the code.

    See also :ref:`determining-types`
