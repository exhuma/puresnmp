Changelog
=========

Release 2.0.0post1 - Maintenance release
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* This fixes the incorrectly provided extra ``rest`` in the dependency
  metadata. This extra has become obsolete and removing it fixed
  versioning errors when installing ``puresnmp``.


Release 2.0 (starting from and including 2.0.0a0)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::
    This is a major upgrade! It is *not* compatible with client-code based on
    puresnmp v1.x

    Refer to :py:ref:`upgrading` for details

* **[changed]** Changed back from ``poetry`` to ``setuptools`` due to too many
  stumbling blocks during development with ``poetry``.
* **[changed]** Main API functions moved into "client" classes
  :py:class:`~puresnmp.api.raw.Client` and
  :py:class:`~puresnmp.api.pythonic.PyWrapper`. See :ref:`upgrading`.
* **[changed]** Extracted ``x690`` processing into separate package
  :py:mod:`x690`. This changed the behaviour of
  :py:class:`x690.types.ObjectIdentifier`
* **[changed]** "continuing" OIDs of bulk-walks removed from logging. This
  caused too much noise in general and was only useful during development of
  puresnmp itself.
* **[changed]** The old inconsistent "VarBind" class has been split into
  :py:class:`puresnmp.varbind.VarBind` and
  :py:class:`puresnmp.varbind.PyVarBind`
* **[changed]** Some data-types now correctly wrap ``None`` instead of ``b""``:

  * NoSuchObject
  * NoSuchInstance
  * EndOfMibView

* **[added]** Type-Hints for table and bulktable calls

  It is now possible to attach a "TypedDict" reference to [bulk]table calls via
  the ``_rowtype`` argument.

* **[added]** Support for SNMPv3

  * Builting support for auth-protocols "md5" and "sha1".
  * Encryption provided by the plugin package :py:mod:`puresnmp-crypto`.
    Installable by activating the ``[crypto]`` "extra" in your dependencies.

* **[added]** Plugin based architecure to support multiple protocols (see
  :py:ref:`plugins`)
* **[added]** Builtin support for the SNMP IPv4 data-type. IPv6 has no defined
  data-type in the context of SNMP. Instead it is defined in a separate RFC/MIB
  which is why it is not inclued.
* **[added]** New exception types based on :rfc:`3416`
* **[added]** Allow temporarily overriding client defaults via
  :py:meth:`puresnmp.api.raw.Client.reconfigure`



Release 1.10.2.post1
~~~~~~~~~~~~~~~~~~~~

This is a "house-keeping" commit. No new features or fixes are introduced.

* **[changed]** Packaging and publishing switched over to poetry

Release 1.10.2
~~~~~~~~~~~~~~~~~~~

* **[fixed]** Speed improvements for overflowing counters (See #88 by Alexey
  Minevich)


Release 1.10.1
~~~~~~~~~~~~~~~~~~~

* **[fixed]** Don't crash with an ``IndexError`` when an error-status is
  returned from a device without specifying an offending OID (See #89 by
  Lopolio)


Release 1.10.0
~~~~~~~~~~~~~~~~~~~

* **[support]** Expose SNMP "version" argument to more API endpoints for
  extended SNMPv1 support (See #87 by Nikolaj Rahbek). Impacted functions are:

  * ``puresnmp.api.pythonic.get()``
  * ``puresnmp.api.pythonic.getnext()``
  * ``puresnmp.api.pythonic.walk()``
  * ``puresnmp.api.pythonic.set()``
  * ``puresnmp.api.pythonic.multiset()``
  * ``puresnmp.api.raw.get()``
  * ``puresnmp.api.raw.getnext()``
  * ``puresnmp.api.raw.set()``
  * ``puresnmp.api.raw.multiset()``


Release 1.9.1
~~~~~~~~~~~~~~~~~~~

* **[fixed]** Fix a regression introduced by 1.9 causing exception message to
  get dropped (#85)

Release 1.9.0.post1
~~~~~~~~~~~~~~~~~~~

* **[docs]** Add dummy changelog entry for 1.8.0

Release 1.9.0
~~~~~~~~~~~~~

* **[added]** Added ``TrapInfo.origin`` containing the IP-address of the host
  emitting the SNMP Trap (See #79, by Richard Smith).
* **[added]** Allow specifying the SNMP version on "set" operations (See #77,
  by Mischa Spiegelmock).
* **[added]** Support for SNMPv1 for ``multigetnext`` (by Mischa Spiegelmock)
* **[support]** Better(?) type hinting
* **[support]** Introdce ``puresnmp.snmp`` with SNMP-specific data structures
  (refactored out from ``puresnmp.pdu``.
* **[support]** Some unit-test house-keeping for Python < 3.6


Release 1.8.0
~~~~~~~~~~~~~

This release never existed due to a mixup with the package version in a
pull-request.

Release 1.7.4
~~~~~~~~~~~~~

* **[fixed]** Removed a regression from 1.7.0: Table outputs should be lists in
  the 1.x branch as documented (#74)
* **[fixed]** Removed a type-hint which tripped up mypy (#75)
* **[fixed]** Fix decoding of unsigned integer values (#76)


Release 1.7.3
~~~~~~~~~~~~~

* **[support]** Make ``bulktable()`` available via the package root (#73)

Release 1.7.2
~~~~~~~~~~~~~

* **[fixed]** Fixed a regression introduced in 1.6.3 (commit 7e559d5d) causing
  modified values for ``BUFFER_SIZE`` and ``RETRIES`` to be ignored.

Release 1.7.1
~~~~~~~~~~~~~

* **[fixed]** Version 1.7.0 introduced a regression which caused ``VarBind``
  instances to lose the ability to be indexed. This is now fixed.

Release 1.7.0
~~~~~~~~~~~~~

* **[added]** A new function ``bulktable`` is added to all external APIs:

  * ``puresnmp.api.raw.bulktable``
  * ``puresnmp.api.pythonic.bulktable``
  * ``puresnmp.aio.api.raw.bulktable``
  * ``puresnmp.aio.api.pythonic.bulktable``

  This function returns a pseudo-table (just like the normal ``table``
  function) but uses more efficient SNMP "bulk" requests under the hood.

* **[added]** The library now knows how to deal with "T61" string encodings and
  supports them if they are returned from a device (or sent to a device).
* **[support]** The ``table`` and ``bulktable`` functions no longer require the
  ``num_base_nodes`` argument as it was redundant with the OID. Now, if it is
  used, it will emit a deprecation warning and will be removed in a future
  release.
* **[support]** The ``bulkwalk`` table now also takes an optional timeout
  argument.
* **[support]** The default TCP timeout is now set via the module-level
  variable ``puresnmp.const.DEFAULT_TIMEOUT``. This can still be overridden by
  using the ``timeout`` argument on function calls.
* **[support]** (internal) The X.690 ``tablify`` function now optionally takes
  an OID as table "base", which is easier than passing in the number of
  base-nodes.
* **[fixed]** The "retries" and "buffer_size" arguments were not properly
  handed over to the "transport" layer which is now fixed.
* **[quality]** More automation via GitHub actions (fixed in ``1.7.0.post1``)
* **[quality]** Code cleanup and type hint improvements. But there's still a
  lot of work to be done on the typing front.

Release 1.6.4
~~~~~~~~~~~~~

* **[fixed]** ``puresnmp`` is now also Python 3.8 compatible


Release 1.6.3
~~~~~~~~~~~~~

* **[fixed]** Network socket is now properly closed when the maximum number of
  retries has reached. This fixes emissions of Python resource warnings.


Release 1.6.2
~~~~~~~~~~~~~

* **[support]** *(1.6.2.post1)* - Type hints for
  ``puresnmp.x690.types.ObjectIdentifier`` improved

* **[fixed]** Counter32 and Counter64 values no longer increase above max-value
  and properly wrap back to ``0`` as defined in `RFC-2578 Section 7.1.6
  <https://tools.ietf.org/html/rfc2578#section-7.1.6>`_ and `RFC-2578 Section
  7.1.10 <https://tools.ietf.org/html/rfc2578#section-7.1.10>`_.

  If a value is more than one unit above the max-value the behaviour is
  undefine in that RFC as it assumes monotonically increasing values. As a
  design decision I decided to initialise the value using the overflow amount.
  So a counter initialised to ``40`` above maximum, will have the value ``40``.

Release 1.6.1
~~~~~~~~~~~~~

* **[fixed]** Regression caused in 1.6.0 due to socket timeout argument.

Release 1.6.0
~~~~~~~~~~~~~

* **[new]** SNMPv2 Trap support (see the cookbook for an example).
* **[internal]** Network transport functions are now wrapped by a class.


Release 1.5.2.post1
~~~~~~~~~~~~~~~~~~~

* **[fixed]** Add missing file for PEP-561 compliance.


Release 1.5.2
~~~~~~~~~~~~~

* **[fixed]** No longer raise an exception when using ``snmp.set`` with an
  absolute OID (an OID with leading dot).


Release 1.5.1
~~~~~~~~~~~~~

* **[fixed]** Socket connections no longer read multiple times from the same
  UDP socket. An appropriate error is now raised
  ``puresnmp.x690.exc.InvalidValueLength`` when a returned package is larger
  than the default buffer-size.

  To increase the buffer size, simply set the appropriate value to
  ``puresnmp.transport.BUFFER_SIZE``.


Release 1.5.0
~~~~~~~~~~~~~

* **[new]** The buffer-size of low-level socket calls can now be modified via
  the global variable ``puresnmp.transport.BUFFER_SIZE``.
* **[new]** ``Sequence`` instances are now "sized" (it is now possible to call
  ``len()`` on a sequence).
* **[new]** Applied missing bugfixes to the async code (ensured that the aio
  API behaves the same way as the normal API).
* **[fix]** Properly handle ``endOfMibView`` markers in responses (Issue #54)
* **[fix]** Synced bugfixes of the non-async code with the async code. They
  should now behave identically.
* **[fix]** An error message in ``bulkget`` responses now shows the proper OID
  count.
* **[support]** Reading "ASCII/Hex" files in unit-tests is now a bit more
  flexible and can read more formats.


Release 1.4.1
~~~~~~~~~~~~~

* **[fix]** Fixed a regression which was introduced in ``v1.3.2``


Release 1.4.0
~~~~~~~~~~~~~

* **[new]** PEP 561 compliance (since 1.4.0.post1)
* **[new]** asyncio support via :py:mod:`puresnmp.aio` (Thanks to @acspike).
* **[new]** Much better error detail if the SNMP agent returns a response with
  an error-code. See :py:exc:`puresnmp.exc.ErrorResponse`.
* **[new]** The ``ObjectIdentifier`` class now has two convenience methods
  :py:meth:`~puresnmp.x690.types.ObjectIdentifier.childof` and
  :py:meth:`~puresnmp.x690.types.ObjectIdentifier.parentof`. They merely
  delegat to ``__contains__`` but can make code more readable.


Release 1.3.2
~~~~~~~~~~~~~

* **[fix]** Fixed a regression introduced by `v1.3.1` for Python < 3.6.


Release 1.3.1
~~~~~~~~~~~~~

* **[fix]** Fixed an endless loop caused by some network devices with broken
  SNMP implementations. This will now raise a `FaultySNMPImplementation`
  exception unless `errors=puresnmp.api.raw.ERRORS_WARN` is passed to `walk`
  operations.


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

* **[new]** The SNMP type ``IpAddress`` is now properly transcoded to the
  Python ``IPv4Address`` type (via RFC3416).
* **[changed]** ``NonASN1Type`` is now deprectated. Use ``UnknownType`` instead
  (Royce Mitchell).
* **[fix]** ``ObjectIdentifier(0)`` is now correctly detected & transcoded.
* **[fix]** ``port`` no longer ignores the ``port`` argument.
* **[fix]** Avoid potential error in reported ``OctetString`` length.
* **[fix]** UDP connection retries are now handled properly.
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
