# pylint: skip-file
from __future__ import print_function

import re
import sys
import unittest
from logging import Handler, LogRecord, getLevelName
from os.path import dirname, join
from typing import TYPE_CHECKING

import six

from ..x690.util import to_bytes

if TYPE_CHECKING:
    from typing import Any, Callable, Generator, List, Tuple, TypeVar, Union
    T = TypeVar('T')

try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest  # type: ignore


DATA_DIR = join(dirname(__file__), 'data')

__unittest = True  # <- This disables stack traces in unittest output for
# everything in this module.


class CapturingHandler(Handler):

    def __init__(self):
        # type: () -> None
        super(CapturingHandler, self).__init__()
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
            print('--- Captured log messages:', file=sys.stderr)
            for record in self.captured_records:
                print('Level:', getLevelName(record.levelno), 'Message:',
                      record.msg % record.args, file=sys.stderr)
            raise AssertionError('Pattern %r was not found with level %r in '
                                 'the log records' % (message_regex, level))


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
            raise ValueError('assertBytesEqual requires two bytes objects!')

        if a != b:
            comparisons = []
            type_a = type(a)
            type_b = type(b)
            a = bytearray(a)
            b = bytearray(b)

            def char_repr(c):
                # type: (bytes) -> str
                if 0x1f < char_a < 0x80:
                    # bytearray to prevent accidental pre-mature str conv
                    # str to prevent b'' suffix in repr's output
                    return repr(str(bytearray([char_a]).decode('ascii')))
                return '.'
            for offset, (char_a, char_b) in enumerate(zip_longest(a, b)):
                comp, marker = ('==', '') if char_a == char_b else ('!=', '>>')

                # Using "zip_longest", overflows are marked as "None", which is
                # unambiguous in this case, but we need to handle these
                # separately from the main format string.
                if char_a is None:
                    char_ab = char_ad = char_ah = char_ar = '?'
                else:
                    char_ab = '0b{:08b}'.format(char_a)
                    char_ad = '{:3d}'.format(char_a)
                    char_ah = '0x{:02x}'.format(char_a)
                    char_ar = char_repr(char_a)
                if char_b is None:
                    char_bb = char_bd = char_bh = char_br = '?'
                else:
                    char_bb = '0b{:08b}'.format(char_b)
                    char_bd = '{:3d}'.format(char_b)
                    char_bh = '0x{:02x}'.format(char_b)
                    char_br = char_repr(char_b)
                comparisons.append(
                    "{8:<3} Offset {0:4d}: "
                    "{1:^10} {4} {5:^10} | "
                    "{2:>3} {4} {6:>3} | "
                    "{3:^4} {4} {7:^4} | {9:>3} {4} {10:>3}".format(
                        offset,
                        char_ab,
                        char_ad,
                        char_ah,
                        comp,
                        char_bb,
                        char_bd,
                        char_bh,
                        marker,
                        char_ar,
                        char_br))
            raise AssertionError(
                'Bytes differ!\n' +
                'type(a)=%s, type(b)=%s\n' % (type_a, type_b) +
                '\nIndividual bytes:\n' +
                '\n'.join(comparisons))


def parse_meta_lines(lines):
    # type: (List[str]) -> Generator[Tuple[str, Any], None, None]
    pattern = re.compile(r'-\*-(.*?)-\*-')
    for line in lines:
        match = pattern.search(line)
        if not match:
            continue
        values = match.groups()[0]
        key, _, value = values.partition(':')
        if key.strip() == 'ascii-cols':
            start, _, end = value.partition('-')
            yield key.strip(), (int(start), int(end))
        else:
            yield key.strip(), value.strip()


def chunker(lines, is_boundary):
    # type: (List[T], Callable[[T], bool]) -> Generator[List[T], None, None]
    '''
    Transforms a list of items into a generator of new lists of items of the
    same type by looking for special boundary lines. Boundary lines are
    detected with the help of an "is_boundary" callable.

    Example:

        >>> data = [1, 2, -1, 3, 4]
        >>> for chunk in chunker(data, is_boundary=lambda x: x == -1):
        ...     print(chunk)
        [1, 2]
        [3, 4]
    '''
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
    '''
    Given a list of strings, this will return the most likely positions of byte
    positions. They are returned slice which should be able to extract the
    columns from each line.
    '''
    for line in lines:
        # if the content contains a ":" character, it contains the byte offset
        # in the beginning. This is the case for libsnmp command output using
        # the "-d" switch. We need to remove the offset
        match = re.match(r'^\d{4}:', line)
        if ':' in line:
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

    meta_lines = [line for line in lines if '-*-' in line]
    args = dict(parse_meta_lines(meta_lines))

    if 'ascii-cols' in args:
        ascii_slice = slice(*args['ascii-cols'])
    else:
        ascii_slice = detect_ascii_slice(lines)

    for chunk in chunker(lines, is_boundary=lambda x: x.strip() == '----'):
        wo_comments = [line for line in chunk if not line.startswith('#')]
        without_ascii = [line[ascii_slice] for line in wo_comments]
        nonempty = [line for line in without_ascii if line.strip()]

        str_bytes = []
        for line in nonempty:
            str_bytes.extend(line.split())

        values = [int(char, 16) for char in str_bytes]

        yield to_bytes(values)
        del str_bytes[:]


def readbytes(filename, base_dir=DATA_DIR):
    # type: (str, str) -> bytes
    packets = readbytes_multiple(filename, base_dir)
    return next(packets)
