"""
This module contains the high-level functions to access the library. Care is
taken to make this as pythonic as possible and hide as many of the gory
implementations as possible.
"""


from x690.types import ObjectIdentifier

# !!! DO NOT REMOVE !!! The following import triggers the processing of SNMP
# Types and thus populates the Registry. If this is not included, Non x.690
# SNMP types will not be properly detected!
import puresnmp.types
from puresnmp.api.pythonic import PyWrapper
from puresnmp.api.raw import Client
from puresnmp.credentials import V1, V2C, V3

try:
    import importlib.metadata as importlib_metadata
except ModuleNotFoundError:
    import importlib_metadata  # type: ignore


__version__ = importlib_metadata.version("puresnmp")  # type: ignore

__all__ = [
    "Client",
    "ObjectIdentifier",
    "PyWrapper",
    "V1",
    "V2C",
    "V3",
    "__version__",
]
