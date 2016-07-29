import unittest


class ByteTester(unittest.TestCase):
    def assertBytesEqual(self, a, b):
        """
        Helper method to compare bytes with more helpful output.
        """
        if a != b:
            comparisons = []
            for offset, (char_a, char_b) in enumerate(zip(a, b)):
                comparisons.append(
                    "Offset {:4d}: {:08b} {} {:08b}".format(
                        offset,
                        char_a,
                        '==' if char_a == char_b else '!=',
                        char_b))
            raise AssertionError('\n' + '\n'.join(comparisons))
