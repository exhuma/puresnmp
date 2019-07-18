Catching SNMPv2 Traps
---------------------

Traps are implemented as a generator. A simple "for" loop is enough to start
listening.

Each iteration will yield a pure Python object of
:py:class:`puresnmp.api.pythonic.TrapInfo`.

See :py:func:`puresnmp.api.pythonic.traps` for details.

.. tip:: **Testing Traps**

   If you want to test traps, you can use the Dockerfile provided in the
   repository of puresnmp. See `docker/README.rst`_ for details

.. _docker/README.rst: https://github.com/exhuma/puresnmp/blob/master/docker/README.rst

Basic Example
~~~~~~~~~~~~~

.. code-block:: python

   from puresnmp.api.pythonic import traps

   for trap in traps():
      print('TRAP %r received: ' % trap.oid)
      for oid, value in trap.values.items():
         print('    %r: %r' % (oid, value))


If you prefer while loops
~~~~~~~~~~~~~~~~~~~~~~~~~

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


Parallel Processing
~~~~~~~~~~~~~~~~~~~

While UDP messages are cached by the Linux kernel, we still want to pull them
out of the cache as fast as possible to avoid packet drops. If the handling of
messages is slower than they arrive in the process we may want to parallelise
processing. This can be done with threads or processes. The difference between
these two is out of scope of this document.


Threading
^^^^^^^^^


.. code-block:: python

    from concurrent.futures import ThreadPoolExecutor
    from os import getpid
    from threading import current_thread
    from time import sleep

    from puresnmp import traps


    def process_trap(trap_number, trap):
        """
        Dummy function to simulate long-running task
        """
        ident = current_thread().name
        print('PID=%d Thread=%r: processing trap #%d: %r' %
              (getpid(), ident, trap_number, trap))
        sleep(3)  # simulate long-running task
        print('PID=%d Thread=%r: Done processing trap #%d' %
              (getpid(), ident, trap_number))


    def main():
        executor = ThreadPoolExecutor(max_workers=20)
        print('Listeing with %r' % executor)
        try:
            for i, trap in enumerate(traps()):
                print('PID=%d Thread=%r got %r' %
                      (getpid(), current_thread().name, trap))
                executor.submit(process_trap, i, trap)
        finally:
            print('Waiting for threads to finish up...')
            executor.shutdown()


    if __name__ == '__main__':
        main()


Processes
^^^^^^^^^


.. code-block:: python

    from concurrent.futures import ProcessPoolExecutor
    from os import getpid
    from threading import current_thread
    from time import sleep

    from puresnmp import traps


    def process_trap(trap_number, trap):
        """
        Dummy function to simulate long-running task
        """
        ident = current_thread().name
        print('PID=%d Thread=%r: processing trap #%d: %r' %
              (getpid(), ident, trap_number, trap))
        sleep(3)  # simulate long-running task
        print('PID=%d Thread=%r: Done processing trap #%d' %
              (getpid(), ident, trap_number))


    def main():
        executor = ProcessPoolExecutor(max_workers=5)
        ident = current_thread().name
        print('Listeing with %r' % executor)
        try:
            for i, trap in enumerate(traps()):
                print('PID=%d Thread=%r: got %r' % (getpid(), ident, trap))
                executor.submit(process_trap, i, trap)
        finally:
            print('Waiting for processes to finish up...')
            executor.shutdown()


    if __name__ == '__main__':
        main()
