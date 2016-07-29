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
            for offset, (char_a, char_b) in enumerate(zip(a, b)):
                comp, marker = ('==', '') if char_a == char_b else ('!=', '>>')

                comparisons.append(
                    "{4:<3} Offset {0:4d}: "
                    "0b{1:08b} {2} 0b{3:08b} | "
                    "{1:3d} {2} {3:3d} | "
                    "0x{1:02x} {2} 0x{3:02x}".format(
                        offset,
                        char_a,
                        comp,
                        char_b,
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
