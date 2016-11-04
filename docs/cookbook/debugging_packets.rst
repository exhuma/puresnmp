Debugging Packets
-----------------

Sometimes it might be useful to see packets (or a representaion thereof) which
are sent out on the network.

Knowing that the network code is localised to :py:mod:`puresnmp.transport`, we
can set a simple breakpoint using ``pdb``::


    $ python -m pdb my_script.py
    (pdb) from puresnmp.transport import send
    (pdb) b send
    Breakpoint 1 at /.../transport.py:23
    (Pdb) c

After running this, the application will stop inside the function sending
packets onto the net. We can inspect the raw packet::

    (pdb) print(packet)

Or, go up a frame and look at the Python structure representing the packet::

    (pdb) up
    ...
    (pdb) print(packet.pretty())
