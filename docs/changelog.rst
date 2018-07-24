Changelog
=========


Release 1.3.0
~~~~~~~~~~~~~

* **[new]** Python 2 support (Royce Mitchell).
* **[new]** Expose ``timeout`` argument in additional functions.
* **[new]** Walk operations now yield rows as they come in over the network
  instead of materialising them in memory (Royce Mitchell).
* **[new]** Introduce ``puresnmp.api.raw`` with same signatures as ``puresnmp``
  but for for non-pythonized output.
* **[new]** ``ObjectIdentifier.from_string`` now allows a leading ``.``.
* **[new]** Collections of ``ObjectIdentifier`` instances are now sortable.
* **[new]** Enforce ``str`` type in ``ObjectIdentifier.from_string``.
* **[new]** ``ObjectIdentifier`` now supports ``__len__``::

    len(ObjectIdentifier(1, 2, 3)) == 3

* **[new]** ``ObjectIdentifier`` instances can now be converted to ``int`` (if
  they only have one node)::

    int(ObjectIdentifier(5)) == 5

* **[new]** ``ObjectIdentifier`` instances can now be concatenated using
  ``+``::

    ObjectIdentifier(1) + ObjectIdentifier(2) == ObjectIdentifier(1, 2)

* **[new]** ``ObjectIdentifier`` instances are now indexable::

    ObjectIdentifier(1, 2, 3)[1] == ObjectIdentifier(2)

* **[changed]** ``NonASN1Type`` is now deprectated. Use ``UnknownType`` instead
  (Royce Mitchell).
* **[fix]** ``ObjectIdentifier(0)`` is now correctly detected & transcoded.
* **[fix]** ``port`` no longer ignores the ``port`` argument.
* **[fix]** Avoid potential error in reported ``OctetString`` length.
* **[code-quality]** Improved type-hints.
* **[code-quality]** Update contribution guide, adding code-style rules. Added
  an appropriate ``pylintrc`` and fixed some style violations.

Release 1.2.1
~~~~~~~~~~~~~

* Clarify error message if a ``bulkwalk`` is requested with non-iterable OIDs.

Release 1.2.0
~~~~~~~~~~~~~

* Exposed access to the ``timeout`` value. Each SNMP call not takes an optional
  ``timeout`` value which specifies the timeout in seconds (Thomas Kirsch).


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

Notable bugfixes on the 1.1.x branch
####################################

* Some internal types leaked to the outside. This is no longer the case (fixed
  in ``v1.1.1``)
* Raw packets are logged using the ``DEBUG`` level ("fixed" in ``v1.1.1``).
* Fixed encoding of long length values (fixed in ``v1.1.2``)
* ``v1.1.3`` added minor internal fixes.
* Fixed IP-Address Header (fixed in ``v1.1.4``)
* Fixed signed integers (fixed in ``v1.1.5``)
