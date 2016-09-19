.. _cookbook:

Cookbook
========

.. note:: Note on Types

    In the current version, some types internal to SNMP and :term:`X.690` are
    abstracted away. But not all of them yet. One goal of the library is to act
    as a border between pure Python code and SNMP internals. It is not always
    possible to hide the type information. Especially on ``SET`` requests.

    "Hiding" these types while still retaining access to them if needed, is a
    work in progress!

    Additionally, not *all* core types are yet supported. In this case a
    ``NonASN1Type`` will be returned. This instance contains the type
    information byte and the raw bytes value.


SNMP Get
--------

Python Code
~~~~~~~~~~~

.. code-block:: python

    from puresnmp import get

    IP = "127.0.0.1"
    COMMUNITY = 'private'
    OID = '1.3.6.1.2.1.1.2.0'

    result = get(IP, COMMUNITY, OID)

    print('''Get Result:
        Type: %s
        repr: %r
        str: %s
        ''' % (type(result), result, result))

Output
~~~~~~


.. code-block:: text

    Get Result:
            Type: <class 'str'>
            repr: '1.3.6.1.4.1.8072.3.2.10'
            str: 1.3.6.1.4.1.8072.3.2.10


SNMP Walk
---------

Python Code
~~~~~~~~~~~

.. code-block:: python

    from puresnmp import walk

    IP = "127.0.0.1"
    COMMUNITY = 'private'
    OID = '1.3.6.1.2.1.1.9.1'

    for row in walk(IP, COMMUNITY, OID):
        print('%s: %r' % row)


Output
~~~~~~

.. code-block:: text

    1.3.6.1.2.1.1.9.1.2.1: ObjectIdentifier((1, 3, 6, 1, 6, 3, 11, 3, 1, 1))
    1.3.6.1.2.1.1.9.1.2.2: ObjectIdentifier((1, 3, 6, 1, 6, 3, 15, 2, 1, 1))
    1.3.6.1.2.1.1.9.1.2.3: ObjectIdentifier((1, 3, 6, 1, 6, 3, 10, 3, 1, 1))
    1.3.6.1.2.1.1.9.1.2.4: ObjectIdentifier((1, 3, 6, 1, 6, 3, 1))
    1.3.6.1.2.1.1.9.1.2.5: ObjectIdentifier((1, 3, 6, 1, 2, 1, 49))
    1.3.6.1.2.1.1.9.1.2.6: ObjectIdentifier((1, 3, 6, 1, 2, 1, 4))
    1.3.6.1.2.1.1.9.1.2.7: ObjectIdentifier((1, 3, 6, 1, 2, 1, 50))
    1.3.6.1.2.1.1.9.1.2.8: ObjectIdentifier((1, 3, 6, 1, 6, 3, 16, 2, 2, 1))
    1.3.6.1.2.1.1.9.1.2.9: ObjectIdentifier((1, 3, 6, 1, 6, 3, 13, 3, 1, 3))
    1.3.6.1.2.1.1.9.1.2.10: ObjectIdentifier((1, 3, 6, 1, 2, 1, 92))
    1.3.6.1.2.1.1.9.1.3.1: OctetString(b'The MIB for Message Processing and Dispatching.')
    1.3.6.1.2.1.1.9.1.3.2: OctetString(b'The management information definitions for the SNMP User-based Security Model.')
    1.3.6.1.2.1.1.9.1.3.3: OctetString(b'The SNMP Management Architecture MIB.')
    1.3.6.1.2.1.1.9.1.3.4: OctetString(b'The MIB module for SNMPv2 entities')
    1.3.6.1.2.1.1.9.1.3.5: OctetString(b'The MIB module for managing TCP implementations')
    1.3.6.1.2.1.1.9.1.3.6: OctetString(b'The MIB module for managing IP and ICMP implementations')
    1.3.6.1.2.1.1.9.1.3.7: OctetString(b'The MIB module for managing UDP implementations')
    1.3.6.1.2.1.1.9.1.3.8: OctetString(b'View-based Access Control Model for SNMP.')
    1.3.6.1.2.1.1.9.1.3.9: OctetString(b'The MIB modules for managing SNMP Notification, plus filtering.')
    1.3.6.1.2.1.1.9.1.3.10: OctetString(b'The MIB module for logging SNMP Notifications.')
    1.3.6.1.2.1.1.9.1.4.1: NonASN1Type(67, b'\x00')
    1.3.6.1.2.1.1.9.1.4.2: NonASN1Type(67, b'\x00')
    1.3.6.1.2.1.1.9.1.4.3: NonASN1Type(67, b'\x00')
    1.3.6.1.2.1.1.9.1.4.4: NonASN1Type(67, b'\x00')
    1.3.6.1.2.1.1.9.1.4.5: NonASN1Type(67, b'\x00')
    1.3.6.1.2.1.1.9.1.4.6: NonASN1Type(67, b'\x00')
    1.3.6.1.2.1.1.9.1.4.7: NonASN1Type(67, b'\x00')
    1.3.6.1.2.1.1.9.1.4.8: NonASN1Type(67, b'\x00')
    1.3.6.1.2.1.1.9.1.4.9: NonASN1Type(67, b'\x00')
    1.3.6.1.2.1.1.9.1.4.10: NonASN1Type(67, b'\x00')


SNMP Set
--------

Python Code
~~~~~~~~~~~

.. code-block:: python

    from puresnmp import set
    from puresnmp.x690.types import OctetString

    IP = "127.0.0.1"
    COMMUNITY = 'private'
    OID = '1.3.6.1.2.1.1.4.0'

    result = set(IP, COMMUNITY, OID, OctetString(b'I am contact'))
    print(repr(result))


Output
~~~~~~

.. code-block:: text

    b'I am contact'
