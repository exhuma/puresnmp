# pylint: disable=redefined-builtin
# pylint: disable=invalid-name
"""
This module contains the high-level functions to access the library. Care is
taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.
"""


# !!! DO NOT REMOVE !!! The following import triggers the processing of SNMP
# Types and thus populates the Registry. If this is not included, Non x.690
# SNMP types will not be properly detected!
import puresnmp.types
from puresnmp.api.pythonic import (
    bulkget,
    bulktable,
    bulkwalk,
    get,
    getnext,
    multiget,
    multigetnext,
    multiset,
    multiwalk,
    set,
    table,
    traps,
    walk,
)
