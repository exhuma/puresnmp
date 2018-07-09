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


Using libsnmp Commands on a Custom Port
=======================================

When using a random port you need to specify it in the ``libsnmp`` commands as
follows (assuming it's ``33213`` in this example)::

    snmpwalk [...] 127.0.0.1:33213 [...]
