"""
This module provides the plugin for SHA-224-based authentication
(usmHMAC128SHA224AuthProtocol, :rfc:`7860`)
"""

import hashlib

from puresnmp.util import password_to_key
from puresnmp_plugins.auth import hashbase

IDENTIFIER = "sha224"
IANA_ID = 4

#: The number of octets of the HMAC sent in the authentication parameters
DIGEST_LENGTH = 16

hasher = password_to_key(hashlib.sha224, 28)

#: Compare incoming message digest with expected value. Return True if the
#: digest matches the expected value.
authenticate_incoming_message = hashbase.for_incoming(
    hasher, "sha224", digest_length=DIGEST_LENGTH
)

#: Calculate the message digest for a SNMPv3 message.
authenticate_outgoing_message = hashbase.for_outgoing(
    hasher, "sha224", digest_length=DIGEST_LENGTH
)
