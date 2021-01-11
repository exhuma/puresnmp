import hashlib

import puresnmp.auth.hashbase as hashbase
from puresnmp.util import password_to_key

IDENTIFIER = "sha1"

hasher = password_to_key(hashlib.sha1, 20)
authenticate_incoming_message = hashbase.for_incoming(hasher, "sha1")
authenticate_outgoing_message = hashbase.for_outgoing(hasher, "sha1")