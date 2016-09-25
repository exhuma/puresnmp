Design Decisions
================

MIBs & ASN.1
------------

The library does not depend on an :term:`ASN.1` library, nor does it parse
:term:`MIBs`.  Everything that's defined in :term:`ASN.1` notation which is
pertinent to SNMP has been hardcoded into the library.

Rationale:

This started off as a proof of concept that it was doable to drop these
dependencies. They complicate the code-base and are not really necessary. It is
unlikely that SNMP will change in such a fundamental level that the
:term:`ASN.1` definitions would need to change. If this happens, these changes
can be made to the code without parsing an :term:`ASN.1` document.

:term:`MIBs`, which are also written in :term:`ASN.1` notation, are also not
necessary for SNMP in its lowest level. :term:`MIBs` can be considered as
"syntactic sugar" for SNMP users. It is not impossible though to wrap this
library in another library and add :term:`MIB` handling. This is however out of
scope of this project.


libsnmp
-------

``libsnmp`` is the de-facto standard for SNMP applications. It is written in C
and very fast. Bindings for Python exist, but using these libraries complicates
installation. Removing this dependency makes installation trivial (it's pure
Python) and the library can be run anywhere where Python can run.

My educated guess is that the drop in performance should be negligeable as the
network traffic *should* always be slower.


External API
------------

The library should expose an API that's as clean as possible. The idea is to
take pure Python data types as input arguments and return pure Python data
types as response. Library details should be hidden away as much as possible.

However, it *should* be kept easy to extend the library, and also give access
to the underlying data structures if needed by offering lower-level functions.
