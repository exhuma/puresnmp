"""
This module contains data-types and helpers which are proper to the SNMP
protocol and independent of X.690
"""
# Error messages as defined in https://tools.ietf.org/html/rfc3416#section-3
ERROR_MESSAGES = {
    0: "(noError)",
    1: "(tooBig)",
    2: "(noSuchName)",
    3: "(badValue)",
    4: "(readOnly)",
    5: "(genErr)",
    6: "(noAccess)",
    7: "(wrongType)",
    8: "(wrongLength)",
    9: "(wrongEncoding)",
    10: "(wrongValue)",
    11: "(noCreation)",
    12: "(inconsistentValue)",
    13: "(resourceUnavailable)",
    14: "(commitFailed)",
    15: "(undoFailed)",
    16: "(authorizationError)",
    17: "(notWritable)",
    18: "(inconsistentName)",
}
