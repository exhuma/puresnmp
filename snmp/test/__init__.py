import unittest


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
                    "0x{1:03x} {2} 0x{3:03x}".format(
                        offset,
                        char_a,
                        comp,
                        char_b,
                        marker))
            raise AssertionError('Bytes differ!\n' + '\n'.join(comparisons))
