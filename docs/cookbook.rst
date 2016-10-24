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

.. note:: 
    For a list of available/implemented types, see :ref:`type_tree`

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


SNMP Table
----------

Python Code
~~~~~~~~~~~

.. code-block:: python

    from pprint import pprint
    from puresnmp import table

    IP = "127.0.0.1"
    COMMUNITY = 'private'
    OID = '1.3.6.1.2.1.2.2'

    result = table(IP, COMMUNITY, OID)
    pprint(result)


Output
~~~~~~

.. code-block:: python

    [{'0': '1',
      '1': Integer(1),
      '10': NonASN1Type(65, b'\x00\xac'),
      '11': NonASN1Type(65, b'\x02'),
      '12': NonASN1Type(65, b'\x00'),
      '13': NonASN1Type(65, b'\x00'),
      '14': NonASN1Type(65, b'\x00'),
      '15': NonASN1Type(65, b'\x00'),
      '16': NonASN1Type(65, b'\x00\xac'),
      '17': NonASN1Type(65, b'\x02'),
      '18': NonASN1Type(65, b'\x00'),
      '19': NonASN1Type(65, b'\x00'),
      '2': OctetString(b'lo'),
      '20': NonASN1Type(65, b'\x00'),
      '21': NonASN1Type(66, b'\x00'),
      '22': ObjectIdentifier((0, 0)),
      '3': Integer(24),
      '4': Integer(65536),
      '5': NonASN1Type(66, b'\x00\x98\x96\x80'),
      '6': OctetString(b''),
      '7': Integer(1),
      '8': Integer(1),
      '9': NonASN1Type(67, b'\x00')},
     {'0': '10',
      '1': Integer(10),
      '10': NonASN1Type(65, b'\x00\xb9_'),
      '11': NonASN1Type(65, b'\x01\x9a'),
      '12': NonASN1Type(65, b'\x00'),
      '13': NonASN1Type(65, b'\x00'),
      '14': NonASN1Type(65, b'\x00'),
      '15': NonASN1Type(65, b'\x00'),
      '16': NonASN1Type(65, b'\x00\x85\x7f'),
      '17': NonASN1Type(65, b'\x01%'),
      '18': NonASN1Type(65, b'\x00'),
      '19': NonASN1Type(65, b'\x00'),
      '2': OctetString(b'eth0'),
      '20': NonASN1Type(65, b'\x00'),
      '21': NonASN1Type(66, b'\x00'),
      '22': ObjectIdentifier((0, 0)),
      '3': Integer(6),
      '4': Integer(1500),
      '5': NonASN1Type(66, b'\x00\xff\xff\xff\xff'),
      '6': OctetString(b'\x02B\xac\x11\x00\x02'),
      '7': Integer(1),
      '8': Integer(1),
      '9': NonASN1Type(67, b'\x00')}]


SNMP Bulk Get
-------------

Python Code
~~~~~~~~~~~

See :py:func:`puresnmp.bulkget`

.. code-block:: python

    from puresnmp import bulkget
    from pprint import pprint
    ip = '127.0.0.1'
    community = 'private'
    result = bulkget(ip,
                     community,
                     scalar_oids=['1.3.6.1.2.1.1.1', '1.3.6.1.2.1.1.2'],
                     repeating_oids=['1.3.6.1.2.1.3.1', '1.3.6.1.2.1.5.1'],
                     max_list_size=10)
    pprint(result.scalars)
    pprint(result.listing)


Output
~~~~~~

.. code-block:: python

    {'1.3.6.1.2.1.1.1.0': b'Linux 7e68e60fe303 4.4.0-28-generic #47-Ubuntu SMP F'
                          b'ri Jun 24 10:09:13 UTC 2016 x86_64',
     '1.3.6.1.2.1.1.2.0': '1.3.6.1.4.1.8072.3.2.10'}
    OrderedDict([('1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1', 10),
                 ('1.3.6.1.2.1.5.1.0', b'\x01'),
                 ('1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1', b'\x02B\xe2\xc5\x8d\t'),
                 ('1.3.6.1.2.1.5.2.0', b'\x00'),
                 ('1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1', b'\xac\x11\x00\x01'),
                 ('1.3.6.1.2.1.5.3.0', b'\x00'),
                 ('1.3.6.1.2.1.4.1.0', 1),
                 ('1.3.6.1.2.1.5.4.0', b'\x01'),
                 ('1.3.6.1.2.1.4.3.0', b'\x04\xc6'),
                 ('1.3.6.1.2.1.5.5.0', b'\x00'),
                 ('1.3.6.1.2.1.4.4.0', b'\x00'),
                 ('1.3.6.1.2.1.5.6.0', b'\x00'),
                 ('1.3.6.1.2.1.4.5.0', b'\x00'),
                 ('1.3.6.1.2.1.5.7.0', b'\x00'),
                 ('1.3.6.1.2.1.4.6.0', b'\x00'),
                 ('1.3.6.1.2.1.5.8.0', b'\x00'),
                 ('1.3.6.1.2.1.4.7.0', b'\x00'),
                 ('1.3.6.1.2.1.5.9.0', b'\x00'),
                 ('1.3.6.1.2.1.4.8.0', b'\x00'),
                 ('1.3.6.1.2.1.5.10.0', b'\x00')])
