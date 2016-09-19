Status of the Project
=====================

The project is currently in "alpha" state. Meaning, it has been tested only by
me on a limited infrastructure and not all planned features are implemented.

Implemented Features
--------------------

* SNMP v2c GET
* SNMP v2c WALK (and, implicitly GETNEXT as well)
* SNMP v2c SET

Tests executed on
-----------------

* A docker maching running ``snmpd`` (the Dockerfile can be found in the
  ``docker`` folder).
* An Alcatel 7750SR12 box.

Missing Features
----------------

These features are planned but not yet implemented. In order of priority:

* SNMP Table Support without MIBs.
* SNMP Bulk GET support
* SNMPv3.

If you want to help move the project forward, please see the "CONTRIBUTING.rst"
file.
