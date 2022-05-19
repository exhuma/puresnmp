"""
This module provides the plugin for SHA-based authentication
"""
import hashlib

import puresnmp_plugins.auth.hashbase as hashbase
from puresnmp.util import password_to_key

IDENTIFIER = "sha1"
IANA_ID = 3

hasher = password_to_key(hashlib.sha1, 20)

#: Compare incoming message digest with expected value. Return True if the
#: digest matches the expected value.
authenticate_incoming_message = hashbase.for_incoming(hasher, "sha1")

#: Calculate the message digest for a SNMPv3 message.
authenticate_outgoing_message = hashbase.for_outgoing(hasher, "sha1")
