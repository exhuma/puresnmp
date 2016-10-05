from itertools import zip_longest
from os.path import dirname, join
import unittest

DATA_DIR = join(dirname(__file__), 'data')

__unittest = True  # <- This disables stack traces in unittest output for
                   # everything in this module.


class ByteTester(unittest.TestCase):
    def assertBytesEqual(self, a, b):
        """
        Helper method to compare bytes with more helpful output.
        """
        if not isinstance(a, bytes) or not isinstance(b, bytes):
            raise ValueError('assertBytesEqual requires two bytes objects!')

        if a != b:
            comparisons = []
            for offset, (char_a, char_b) in enumerate(zip_longest(a, b)):
                comp, marker = ('==', '') if char_a == char_b else ('!=', '>>')

                # Using "zip_longest", overflows are marked as "None", which is
                # unambiguous in this case, but we need to handle these
                # separately from the main format string.
                if char_a is None:
                    char_ab = char_ad = char_ah = '?'
                else:
                    char_ab = '0b{:08b}'.format(char_a)
                    char_ad = '{:3d}'.format(char_a)
                    char_ah = '0x{:02x}'.format(char_a)

                if char_b is None:
                    char_bb = char_bd = char_bh = '?'
                else:
                    char_bb = '0b{:08b}'.format(char_b)
                    char_bd = '{:3d}'.format(char_b)
                    char_bh = '0x{:02x}'.format(char_b)

                comparisons.append(
                    "{8:<3} Offset {0:4d}: "
                    "{1:^10} {4} {5:^10} | "
                    "{2:>3} {4} {6:>3} | "
                    "{3:^4} {4} {7:^4}".format(
                        offset,
                        char_ab,
                        char_ad,
                        char_ah,
                        comp,
                        char_bb,
                        char_bd,
                        char_bh,
                        marker))
            raise AssertionError('Bytes differ!\n' +
                                 'type(a)=%s, type(b)=%s\n' % (type(a), type(b)) +
                                 '\nIndividual bytes:\n' +
                                 '\n'.join(comparisons))


def readbytes(filename):
    with open(join(DATA_DIR, filename)) as fp:
        lines = fp.readlines()

    ascii_position = 56 if ':' in lines[0] else 50
    without_ascii = [line[:ascii_position] for line in lines]

    str_bytes = []
    for line in without_ascii:
        # if the content contains a ":" character, it contains the byte offset
        # in the beginning. This is the case for libsnmp command output using
        # the "-d" switch. We need to remove the offset
        if ':' in line:
            line = line.split(':')[1]
        str_bytes.extend(line.split())
    values = [int(char, 16) for char in str_bytes]
    return bytes(values)
