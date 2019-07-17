# pylint: disable=redefined-builtin
# pylint: disable=invalid-name
"""
This module contains the high-level functions to access the library. Care is
taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.
"""

from __future__ import unicode_literals

from collections import namedtuple

import verlib

# !!! DO NOT REMOVE !!! The following import triggers the processing of SNMP
# Types and thus populates the Registry. If this is not included, Non x.690
# SNMP types will not be properly detected!
import puresnmp.types
from puresnmp.api.pythonic import (
    bulkget,
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
    walk
)

from .version import VERSION

# Simple version information as text
__version__ = VERSION


# The following line makes the version information available, and also serves
# as a sanity check that the version number is PEP-440 compliant. verlib would
# raise an exception if it isn't!
version_info = verlib.NormalizedVersion(__version__)
