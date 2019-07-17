Catching SNMPv2 Traps
---------------------

Traps are implemented as a generator. A simple "for" loop is enough to start
listening.

Each iteration will yield a pure Python object of
:py:class:`puresnmp.api.pythonic.TrapInfo`.

See :py:func:`puresnmp.api.pythonic.traps` for details.

Python Code
~~~~~~~~~~~

.. code-block:: python

   from puresnmp.api.pythonic import traps

   for trap in traps():
      print('TRAP %r received: ' % trap.oid)
      for oid, value in trap.values.items():
         print('    %r: %r' % (oid, value))


Alternative
^^^^^^^^^^^

.. code-block:: python

   from puresnmp.api.pythonic import traps

   stream = traps()
   while True:
      trap = next(stream)
      print('TRAP %r received: ' % trap.oid)
      for oid, value in trap.values.items():
         print('    %r: %r' % (oid, value))



Output
~~~~~~

Assuming a device sends the Trap ``1.3.6.1.4.1.8072.2.3.0.1`` to us with the
"variable mapping" ``1.3.6.1.4.1.8072.2.3.2.1 = 123456`` then the output will
be the following:

.. code-block:: text

   TRAP '1.3.6.1.4.1.8072.2.3.0.1' received:
        '1.3.6.1.4.1.8072.2.3.2.1': 123456
