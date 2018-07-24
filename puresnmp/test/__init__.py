# pylint: skip-file

import six
import sys
try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest
from os.path import dirname, join
import unittest
from ..x690.util import to_bytes

DATA_DIR = join(dirname(__file__), 'data')

__unittest = True  # <- This disables stack traces in unittest output for
                   # everything in this module.


class ByteTester(unittest.TestCase):
    def assertBytesEqual(self, a, b):
        """
        Helper method to compare bytes with more helpful output.
        """
        def is_bytes(x):
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


def readbytes_multiple(filename):
    with open(join(DATA_DIR, filename)) as fp:
        lines = fp.readlines()

    ascii_position = 56 if ':' in lines[0] else 50
    without_ascii = [line[:ascii_position] for line in lines]
    without_comments = [line for line in without_ascii if not line.startswith('#')]
    nonempty = [line for line in without_comments if line.strip()]

    str_bytes = []
    for line in nonempty:
        # if the content contains a ":" character, it contains the byte offset
        # in the beginning. This is the case for libsnmp command output using
        # the "-d" switch. We need to remove the offset
        if ':' in line:
            line = line.split(':')[1]
        if line.startswith('----'):
            values = [int(char, 16) for char in str_bytes]
            yield to_bytes(values)
            del str_bytes[:]
        else:
            str_bytes.extend(line.split())
    values = [int(char, 16) for char in str_bytes]
    yield to_bytes(values)


def readbytes(filename):
    packets = readbytes_multiple(filename)
    return next(packets)
