Changelog
=========

Release 1.1.0
~~~~~~~~~~~~~

* :py:func:`puresnmp.bulkwalk` and :py:func:`puresnmp.bulkget` have been implemented.
* More "cookbook" examples
* :py:func:`puresnmp.walk` and :py:func:`puresnmp.table` operations now return
  pythonized values (as it should be).
* Types are now properly detected. ``NonASN1Type`` should no longer show up.
* Walking over the end of the OID tree no longer raises an exception.
* SNMP ``TimeTicks`` are now parsed into :py:class:`datetime.timedelta` instances.
* ``port`` is now optional for ``GetNext`` requests (using ``161`` by default)
* VarBinds can now only be created with ``ObjectIdentifier`` or ``str`` instances as first element.
* :py:func:`puresnmp.multiwalk` is now more generic and the backbone of both ``bulkwalk`` and ``walk``.
* Fixed issue with ReadTheDocs
* More unit tests

Internal changes for better RFC3416 conformance
###############################################

* Using real PDU "type" values (tags).
* Renamed "error_code" to "error_status".
* Added error statuses from RFC3416.
* Opaque now inherits from OctetString.
* IpAddress now inherits from OctetString.
* Added support for Counter64 values.
* Raising an error when requesting too many varbinds.
* Renamed ``puresnmp.SnmpMessage`` to :py:class:`puresnmp.PDU`
