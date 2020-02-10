Retrieve Table With Bulk Requests
---------------------------------

See:

* :py:func:`puresnmp.bulktable`

Python Code
~~~~~~~~~~~

.. code-block:: python

    from pprint import pprint
    from puresnmp import bulktable

    IP = '127.0.0.1'
    COMMUNITY = 'private'
    OID = '1.3.6.1.2.1.2.2'

    result = bulktable(IP, COMMUNITY, OID)
    pprint(table)

Output
~~~~~~

.. warning::

    Due to the nature of how tables are constructed, the ordering of rows is
    *not* guaranteed in Python < 3.6!

.. code-block:: python

    [{'0': '1',
      '1': 1,
      '10': 172,
      '11': 2,
      '12': 0,
      '13': 0,
      '14': 0,
      '15': 0,
      '16': 172,
      '17': 2,
      '18': 0,
      '19': 0,
      '2': b'lo',
      '20': 0,
      '21': 0,
      '22': '0.0',
      '3': 24,
      '4': 65536,
      '5': 10000000,
      '6': b'',
      '7': 1,
      '8': 1,
      '9': datetime.timedelta(0)},
     {'0': '10',
      '1': 10,
      '10': 3838306,
      '11': 40136,
      '12': 0,
      '13': 0,
      '14': 0,
      '15': 0,
      '16': 4468174,
      '17': 39356,
      '18': 0,
      '19': 0,
      '2': b'eth0',
      '20': 0,
      '21': 0,
      '22': '0.0',
      '3': 6,
      '4': 1500,
      '5': 4294967295,
      '6': b'\x02B\xac\x11\x00\x02',
      '7': 1,
      '8': 1,
      '9': datetime.timedelta(0)}]
