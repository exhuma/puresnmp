SNMP
====


Quick Info
----------

What
    A pure Python implementation of SNMP without any external dependencies
    (neither MIBs or libsnmp).

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

.. code-block:: python


    import sys
    from puresnmp import walk, set, get
    from puresnmp.x690.types import OctetString

    IP = "::1"
    COMMUNITY = 'private'

    print("Target IP:", IP)


    def run_get():
        if len(sys.argv) > 1:
            OID = sys.argv[1]
        else:
            OID = '1.3.6.1.2.1.1.9.1'

        result = get(IP, COMMUNITY, OID)
        print('''Get Result:
            Type: %s
            repr: %r
            str: %s
            ''' % (type(result), result, result))


    def run_walk():
        if len(sys.argv) > 1:
            OID = sys.argv[1]
        else:
            OID = '1.3.6.1.2.1.1.9.1'

        for row in walk(IP, 'public', OID):
            print('%s: %r' % row)

    def run_set():
        response = set(IP, COMMUNITY, '1.3.6.1.2.1.1.4.0',
                    OctetString(b'I am contact'))


    run_get()




Status of the Project
---------------------

The project is currently in "alpha" state. Meaning, it has been tested only by
me on a limited infrastructure and not all planned features are implemented.

Implemented Features
~~~~~~~~~~~~~~~~~~~~

* SNMP v2c GET
* SNMP v2c WALK
* SNMP v2c SET

Tests executed on
~~~~~~~~~~~~~~~~~

* A docker maching running ``snmpd`` (the Dockerfile can be found in the
  ``docker`` folder).
* An Alcatel 7750SR12 box.

Missing Features
~~~~~~~~~~~~~~~~

* SNMP Bulk GET support
* SNMP operations with multiple OIDs (multiple "var-mappings").
* SNMP Table Support without MIBs.
* SNMPv3.

If you want to help move the project forward, please see the "CONTRIBUTING.rst"
file.


Folders
-------

doc
    Project documentation

puresnmp
    The Python package

docker
    docker image with a very simple SNMP agent to run tests for SNMP
    development.


References
----------

GetNextPDU (and others) explained:
    https://tools.ietf.org/html/rfc1157#section-4.1.3

Page 11 shows a PDU example
    https://tools.ietf.org/html/rfc1592

SNMP uses BER
    https://en.wikipedia.org/wiki/X.690#BER_encoding

PDU Packet Structure
    http://www.tcpipguide.com/free/t_SNMPVersion2SNMPv2MessageFormats-5.htm

MSDN Help
    https://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx

ASCII Representation of some PDUs:
    http://www.opencircuits.com/SNMP_MIB_Implementation

Variable Length Quantity (encoding large numbers)
    https://en.wikipedia.org/wiki/Variable-length_quantity

Settable SNMP Values
    http://tomsalmon.eu/2012/02/net-snmp-writeable-attributes/
