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

__version__ = resource_string('puresnmp',
                              'version.txt').decode('ascii').strip()
