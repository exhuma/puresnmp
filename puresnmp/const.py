"""
This file contains various values used to avoid magic numbers and strings in
the application.
"""
#: Maximum number of usable varbinds as defined in :rfc:`3416`
MAX_VARBINDS = 2147483647

#: A magic value used to detect strict error-handling
ERRORS_STRICT = "strict"

#: A magic value used to detect lenient error-handling
ERRORS_WARN = "warn"

#: TCP timeout which is used if not manually overridden
DEFAULT_TIMEOUT = 6

#: Number of retries we attempt when sending out packets before giving up
DEFAULT_RETRIES = 10

#: The default interface to use when listening to traps. This is flagged with
#: "nosec" as "secure" as this is very much intentional.
DEFAULT_LISTEN_ADDRESS = "0.0.0.0"  # nosec
