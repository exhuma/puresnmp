# pylint: skip-file

import re
import sys
import unittest
from logging import Handler, LogRecord, getLevelName
from os.path import dirname, join
from typing import TYPE_CHECKING

from .conftest import get_byte_diff

if TYPE_CHECKING:
    from typing import Any, Callable, Generator, List, Tuple, TypeVar, Union

    T = TypeVar("T")

try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest  # type: ignore


DATA_DIR = join(dirname(__file__), "data")

__unittest = True  # <- This disables stack traces in unittest output for
# everything in this module.


class CapturingHandler(Handler):
    def __init__(self):
        # type: () -> None
        super().__init__()
        self.captured_records = []  # type: List[LogRecord]

    def emit(self, record):
        # type: (LogRecord) -> None
        self.captured_records.append(record)

    def assertContains(self, level, message_regex):
        # type: (int, str) -> None
        found = False
        for record in self.captured_records:
            matches_level = record.levelno == level
            matches_re = re.search(message_regex, record.msg % record.args)
            if matches_level and matches_re:
                found = True
                break
        if not found:
            print("--- Captured log messages:", file=sys.stderr)
            for record in self.captured_records:
                print(
                    "Level:",
                    getLevelName(record.levelno),
                    "Message:",
                    record.msg % record.args,
                    file=sys.stderr,
                )
            raise AssertionError(
                "Pattern %r was not found with level %r in "
                "the log records" % (message_regex, level)
            )


class ByteTester(unittest.TestCase):
    def assertBytesEqual(self, a, b):
        # type: (Union[bytes, bytearray], Union[bytes, bytearray]) -> None
        """
        Helper method to compare bytes with more helpful output.
        """

        def is_bytes(x):
            # type: (Union[bytes, bytearray]) -> bool
            return isinstance(x, (bytes, bytearray))

        if not is_bytes(a) or not is_bytes(b):
            raise ValueError("assertBytesEqual requires two bytes objects!")

        if a == b:
            return

        difftext = get_byte_diff(a, b)
        if difftext:
            raise AssertionError("\n".join(difftext))


def parse_meta_lines(lines):
    # type: (List[str]) -> Generator[Tuple[str, Any], None, None]
    pattern = re.compile(r"-\*-(.*?)-\*-")
    for line in lines:
        match = pattern.search(line)
        if not match:
            continue
        values = match.groups()[0]
        key, _, value = values.partition(":")
        if key.strip() == "ascii-cols":
            start, _, end = value.partition("-")
            yield key.strip(), (int(start), int(end))
        else:
            yield key.strip(), value.strip()


def chunker(lines, is_boundary):
    # type: (List[T], Callable[[T], bool]) -> Generator[List[T], None, None]
    """
    Transforms a list of items into a generator of new lists of items of the
    same type by looking for special boundary lines. Boundary lines are
    detected with the help of an "is_boundary" callable.

    Example:

        >>> data = [1, 2, -1, 3, 4]
        >>> for chunk in chunker(data, is_boundary=lambda x: x == -1):
        ...     print(chunk)
        [1, 2]
        [3, 4]
    """
    if not lines:
        return

    collected = []  # type: List[T]
    for item in lines:
        if is_boundary(item):
            if collected:
                yield collected
            collected = []
            continue
        else:
            collected.append(item)
    if collected:
        yield collected


def detect_ascii_slice(lines):
    # type: (List[str]) -> slice
    """
    Given a list of strings, this will return the most likely positions of byte
    positions. They are returned slice which should be able to extract the
    columns from each line.
    """
    for line in lines:
        # if the content contains a ":" character, it contains the byte offset
        # in the beginning. This is the case for libsnmp command output using
        # the "-d" switch. We need to remove the offset
        match = re.match(r"^\d{4}:", line)
        if ":" in line:
            return slice(6, 56)
        else:
            return slice(0, 50)
    return slice(0, -1)


def readbytes_multiple(filename, base_dir=DATA_DIR):
    # type: (str, str) -> Generator[bytes, None, None]
    if isinstance(filename, str):
        with open(join(base_dir, filename)) as fp:
            lines = fp.readlines()
    else:
        lines = filename.readlines()

    meta_lines = [line for line in lines if "-*-" in line]
    args = dict(parse_meta_lines(meta_lines))

    if "ascii-cols" in args:
        ascii_slice = slice(*args["ascii-cols"])
    else:
        ascii_slice = detect_ascii_slice(lines)

    for chunk in chunker(lines, is_boundary=lambda x: x.strip() == "----"):
        wo_comments = [line for line in chunk if not line.startswith("#")]
        without_ascii = [line[ascii_slice] for line in wo_comments]
        nonempty = [line for line in without_ascii if line.strip()]

        str_bytes = []
        for line in nonempty:
            str_bytes.extend(line.split())

        values = [int(char, 16) for char in str_bytes]

        yield bytes(values)
        del str_bytes[:]


def readbytes(filename, base_dir=DATA_DIR):
    # type: (str, str) -> bytes
    packets = readbytes_multiple(filename, base_dir)
    return next(packets)
