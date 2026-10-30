"""
This module provides the plugin for SHA-256-based authentication
(usmHMAC192SHA256AuthProtocol, :rfc:`7860`)
"""

import hashlib

from puresnmp.util import password_to_key
from puresnmp_plugins.auth import hashbase

IDENTIFIER = "sha256"
IANA_ID = 5

#: The number of octets of the HMAC sent in the authentication parameters
DIGEST_LENGTH = 24

hasher = password_to_key(hashlib.sha256, 32)

#: Compare incoming message digest with expected value. Return True if the
#: digest matches the expected value.
authenticate_incoming_message = hashbase.for_incoming(
    hasher, "sha256", digest_length=DIGEST_LENGTH
)

#: Calculate the message digest for a SNMPv3 message.
authenticate_outgoing_message = hashbase.for_outgoing(
    hasher, "sha256", digest_length=DIGEST_LENGTH
)
