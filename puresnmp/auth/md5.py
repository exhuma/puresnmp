import hashlib

import puresnmp.auth.hashbase as hashbase
from puresnmp.util import password_to_key

IDENTIFIER = "md5"

hasher = password_to_key(hashlib.md5, 16)
authenticate_incoming_message = hashbase.for_incoming(hasher, "md5")
authenticate_outgoing_message = hashbase.for_outgoing(hasher, "md5")
