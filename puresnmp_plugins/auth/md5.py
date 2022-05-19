"""
This module provides the plugin for MD5-based authentication
"""
import hashlib

import puresnmp_plugins.auth.hashbase as hashbase
from puresnmp.util import password_to_key

IDENTIFIER = "md5"
IANA_ID = 2

hasher = password_to_key(hashlib.md5, 16)

#: Compare incoming message digest with expected value. Return True if the
#: digest matches the expected value.
authenticate_incoming_message = hashbase.for_incoming(hasher, "md5")

#: Calculate the message digest for a SNMPv3 message.
authenticate_outgoing_message = hashbase.for_outgoing(hasher, "md5")
