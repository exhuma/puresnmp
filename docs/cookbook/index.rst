.. _cookbook:

Cookbook
========

.. note:: Note on Types

    In the current version, some types internal to SNMP and :term:`X.690` are
    abstracted away. But not all of them yet (see :ref:`type_tree`). One goal
    of the library is to act as a border between pure Python code and SNMP
    internals. It is not always possible to hide the type information.
    Especially on ``SET`` requests.

    "Hiding" these types while still retaining access to them if needed, is a
    work in progress!

    Additionally, not *all* core types are yet supported. In this case a
    ``NonASN1Type`` will be returned. This instance contains the type
    information byte and the raw bytes value.


.. toctree::
   :maxdepth: 1
   :glob:

   *
