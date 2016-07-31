from itertools import zip_longest
from os.path import dirname, join
import unittest

DATA_DIR = join(dirname(__file__), 'data')


class ByteTester(unittest.TestCase):
    def assertBytesEqual(self, a, b):
        """
        Helper method to compare bytes with more helpful output.
        """
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
            raise AssertionError('Bytes differ!\n' + '\n'.join(comparisons))


def readbytes(filename):
    with open(join(DATA_DIR, filename)) as fp:
        lines = fp.readlines()
    without_ascii = [line[:50] for line in lines]
    str_bytes = []
    for line in without_ascii:
        str_bytes.extend(line.split())
    values = [int(char, 16) for char in str_bytes]
    return bytes(values)
