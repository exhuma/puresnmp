Retrieve Table With Bulk Requests
---------------------------------

See:

* :py:func:`puresnmp.x690.util.tablify`
* :py:func:`puresnmp.bulkwalk`

:py:func:`puresnmp.table` is a convenience wrapper around
:py:func:`puresnmp.walk` and :py:func:`puresnmp.x690.util.tablify`.
:py:func:`~puresnmp.x690.util.tablify` can be used on any walk result, and, by
that definition also over a bulkwalk result!

To turn a bulkwalk result into a table use the following as an example:

.. code-block:: python

    from pprint import pprint
    from puresnmp import bulkwalk
    from puresnmp.x690.util import tablify

    ip = '127.0.0.1'
    community = 'private'
    oids = [
        '1.3.6.1.2.1.2.2.1.2',   # name
        '1.3.6.1.2.1.2.2.1.6',   # MAC
        '1.3.6.1.2.1.2.2.1.22',  # ?
    ]
    result = bulkwalk(ip, community, oids)
    table = tablify(result)
    pprint(table)

Output
~~~~~~

.. code-block:: python

    [{'0': '10', '2': b'eth0', '22': '0.0', '6': b'\x02B\xac\x11\x00\x02'},
     {'0': '1', '2': b'lo', '22': '0.0', '6': b''}]
