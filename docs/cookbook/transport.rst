Control the Low-Level Socket
----------------------------

A couple of aspects of the low-level socket can be configured via a global
variable. The decision to take a global variable was a trade-off between
simplicity and code-quality. I opted for simplicity. The exposed values will
not cause unexpected side-effects.

The two values that can be changed are:

``puresnmp.transport.BUFFER_SIZE``
    Default is set to ``4096``. If you run into unexpected time-outs you may
    need to increase this value.

``puresnmp.transport.RETRIES``
    Default is set to ``3``. How often will a socket be used before giving up.
