Description
===========

This folder contains a dockerfile for a simple machine running an SNMP daemon.
Useful for testing.


Building the Image
==================

The image can simply be built using::

    docker build -t dummy-snmp .


Running the Image
=================

The image is configured to expose the client port 161/udp by default. To make
use of this run the following after building the image::

    docker run -P dummy-snmp

This will expose a *random port* on the host machine and can be useful if the
host itself already has something listening on port ``161``. To find the port
run::

    docker ps

To manually bind the port to something else run::

    docker run -p 161:161/udp dummy-snmp

This will expose the client port ``161`` on the host as port ``161`` as well.


Using the image to send SNMP traps
==================================

The image contains a dummy helper script in ``/usr/local/bin/send_trap``. For
one-shot you can run it directly via docker::

   docker run --rm --network="host" dummy-snmp send_trap

For sending more traps for testing it may by useful to run an interactive shell
in the container and run ``send_trap`` from there::

   docker run -it --rm --network="host" dummy-snmp bash
   root@devbox:/opt/app# send_trap

The script will always send to ``localhost`` so using ``--network=host`` will
send the trap to the docker-host. If you want to change anything look into
``/usr/local/bin/send_trap``


Using libsnmp Commands on a Custom Port
=======================================

When using a random port you need to specify it in the ``libsnmp`` commands as
follows (assuming it's ``33213`` in this example)::

    snmpwalk [...] 127.0.0.1:33213 [...]


Making an SNMPv3 Request
========================

.. code-block::

    snmpget \
        -v3 \
        -l authNoPriv \
        -A theauthpass \
        -u helloworld \
        127.0.0.1:32768 \
        1.3.6.1.2.1.1.2.0

.. code-block::

    snmpget \
        -v3 \
        -l authPriv \
        -A theauthpass \
        -X privpass \
        -u ninja \
        127.0.0.1:32768 \
        1.3.6.1.2.1.1.1.0
