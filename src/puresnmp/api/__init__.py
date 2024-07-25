"""
This package provides two sub-packages:

* :py:mod:`puresnmp.api.pythonic`
  For most applications this is a convenient entry-point.

  A thin wrapper around the "raw" API. This wrapper decouples the code using
  this library from internal data-types. This makes the code more robust
  against internal API changes at the cost of some flexibility and
  performance (more conversions take place)

* :py:mod:`puresnmp.api.raw`

  The underlying lower-level implementation. This layer works primarily with
  internal data-types. It is still high-level enough for most applications.
  But the usage of internal data-types make this less robust against future
  updates.
"""
