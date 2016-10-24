SNMP Set
--------

See :py:func:`puresnmp.set`

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
