## Including hex-dumps in your bug-report

If the issue you are reporting relates to data conversion, or other related
issues about the data transferred over the wire, please include a hexdump of
the data in your bug report.

The easiest way to do this is to enable debug logging:

    import logging
    logging.basicConfig(level=logging.DEBUG)
    <your code under test>

This will display the raw bytes which help a lot in debugging the issue.
