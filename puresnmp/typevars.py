"""
This module contains variour type aliases for type checking
"""
from datetime import datetime, timedelta
from typing import Union

#: This type represents the data type of an SNMP value in the Python worldj.
PyType = Union[str, bytes, int, datetime, timedelta, None]
