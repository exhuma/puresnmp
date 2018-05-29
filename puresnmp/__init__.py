"""
This module contains the high-level functions to access the library. Care is
taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.
"""

from collections import namedtuple

from pkg_resources import resource_string

from puresnmp.api.pythonic import (bulkget, bulkwalk, get, getnext, multiget,
                                   multigetnext, multiset, multiwalk, set,
                                   table, walk)

# !!! DO NOT REMOVE !!! The following import triggers the processing of SNMP
# Types and thus populates the Registry. If this is not included, Non x.690
# SNMP types will not be properly detected!
import puresnmp.types

__version__ = resource_string('puresnmp',
                              'version.txt').decode('ascii').strip()
