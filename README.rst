.. image:: https://travis-ci.org/exhuma/puresnmp.svg?branch=develop
    :target: https://travis-ci.org/exhuma/puresnmp


.. note::

    The development is currently considered as *alpha*! There is no official
    release on pypi yet, but the library is already usable. The main API may
    change, but it already feels solid.

    The library can be directly installed via ``pip`` (see below).

    Obviously bugs may exist. The library is still very young!

----

Quick Info
----------

What
    A pure Python implementation for Python 3.3+ of SNMP without any external
    dependencies (neither MIBs or libsnmp).

Why
    SNMP in itself is simple and well defined. A bit convoluted, but simple.
    MIB parsing however complicates the code-base and is *technically* not
    required. They add typing information and variables and give names to OIDs.
    All existing libraries have a direct or indirect dependency on libsnmp.
    With all the advantages and disadvantages.

    The aim of this project is to focus on SNMP in itself and provide a very
    simple API. Instead of implementing ASN.1 parsing, the SNMP related ASN.1
    and X.690 information is hard-coded (keeping in mind that all that's
    hard-coded is well defined).

    It is of course possible to *wrap* this package in another package adding
    MIB parsing and processing. This is, and will be however **out of the scope
    of this project**!

When
    First commit: Sat Jul 23 12:01:05 2016 +0200

Who
    Michel Albert


Installation
------------

::

    pip install https://github.com/exhuma/puresnmp/archive/develop.zip


Example Usage
-------------

SNMP Get
~~~~~~~~

.. code-block:: python

    from puresnmp import get

    IP = "::1"
    COMMUNITY = 'private'
    OID = '1.3.6.1.2.1.1.9.1'

    result = get(IP, COMMUNITY, OID)

    print('''Get Result:
        Type: %s
        repr: %r
        str: %s
        ''' % (type(result), result, result))


SNMP Walk
~~~~~~~~~

.. code-block:: python

    from puresnmp import walk

    IP = "::1"
    COMMUNITY = 'private'
    OID = '1.3.6.1.2.1.1.9.1'

    for row in walk(IP, COMMUNITY, OID):
        print('%s: %r' % row)


SNMP Set
~~~~~~~~

.. code-block:: python

    from puresnmp import set
    from puresnmp.x690.types import OctetString

    IP = "::1"
    COMMUNITY = 'private'
    OID = '1.3.6.1.2.1.1.4.0'

    result = set(IP, COMMUNITY, OID, OctetString(b'I am contact'))
    print(result)
