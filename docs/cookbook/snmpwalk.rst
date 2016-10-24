SNMP Walk
---------

See :py:func:`puresnmp.walk`

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

    1.3.6.1.2.1.1.9.1.2.1: '1.3.6.1.6.3.11.3.1.1'
    1.3.6.1.2.1.1.9.1.2.2: '1.3.6.1.6.3.15.2.1.1'
    1.3.6.1.2.1.1.9.1.2.3: '1.3.6.1.6.3.10.3.1.1'
    1.3.6.1.2.1.1.9.1.2.4: '1.3.6.1.6.3.1'
    1.3.6.1.2.1.1.9.1.2.5: '1.3.6.1.2.1.49'
    1.3.6.1.2.1.1.9.1.2.6: '1.3.6.1.2.1.4'
    1.3.6.1.2.1.1.9.1.2.7: '1.3.6.1.2.1.50'
    1.3.6.1.2.1.1.9.1.2.8: '1.3.6.1.6.3.16.2.2.1'
    1.3.6.1.2.1.1.9.1.2.9: '1.3.6.1.6.3.13.3.1.3'
    1.3.6.1.2.1.1.9.1.2.10: '1.3.6.1.2.1.92'
    1.3.6.1.2.1.1.9.1.3.1: b'The MIB for Message Processing and Dispatching.'
    1.3.6.1.2.1.1.9.1.3.2: b'The management information definitions for the SNMP User-based Security Model.'
    1.3.6.1.2.1.1.9.1.3.3: b'The SNMP Management Architecture MIB.'
    1.3.6.1.2.1.1.9.1.3.4: b'The MIB module for SNMPv2 entities'
    1.3.6.1.2.1.1.9.1.3.5: b'The MIB module for managing TCP implementations'
    1.3.6.1.2.1.1.9.1.3.6: b'The MIB module for managing IP and ICMP implementations'
    1.3.6.1.2.1.1.9.1.3.7: b'The MIB module for managing UDP implementations'
    1.3.6.1.2.1.1.9.1.3.8: b'View-based Access Control Model for SNMP.'
    1.3.6.1.2.1.1.9.1.3.9: b'The MIB modules for managing SNMP Notification, plus filtering.'
    1.3.6.1.2.1.1.9.1.3.10: b'The MIB module for logging SNMP Notifications.'
    1.3.6.1.2.1.1.9.1.4.1: datetime.timedelta(0, 0, 50000)
    1.3.6.1.2.1.1.9.1.4.2: datetime.timedelta(0, 0, 50000)
    1.3.6.1.2.1.1.9.1.4.3: datetime.timedelta(0, 0, 50000)
    1.3.6.1.2.1.1.9.1.4.4: datetime.timedelta(0, 0, 50000)
    1.3.6.1.2.1.1.9.1.4.5: datetime.timedelta(0, 0, 50000)
    1.3.6.1.2.1.1.9.1.4.6: datetime.timedelta(0, 0, 50000)
    1.3.6.1.2.1.1.9.1.4.7: datetime.timedelta(0, 0, 50000)
    1.3.6.1.2.1.1.9.1.4.8: datetime.timedelta(0, 0, 50000)
    1.3.6.1.2.1.1.9.1.4.9: datetime.timedelta(0, 0, 60000)
    1.3.6.1.2.1.1.9.1.4.10: datetime.timedelta(0, 0, 60000)
