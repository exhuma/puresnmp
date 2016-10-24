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
