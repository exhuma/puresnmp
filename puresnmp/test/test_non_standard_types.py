from datetime import timedelta

from . import ByteTester

from .. import types as t


class TestTimeTicks(ByteTester):

    def test_decoding(self):
        result = t.TimeTicks.from_bytes(b'\x43\x01\x0a')
        expected = t.TimeTicks(10)
        self.assertEqual(result, expected)

    def test_encoding(self):
        value = t.TimeTicks(100)
        result = bytes(value)
        expected = b'\x43\x01\x64'
        self.assertBytesEqual(result, expected)

    def test_conversion_to_python(self):
        # NOTE: 41 centiseconds = 410000 microseconds
        result = t.TimeTicks(18890041).pythonize()
        expected = timedelta(days=2, hours=4, minutes=28, seconds=20,
                             microseconds=410000)
        self.assertEqual(result, expected)

    def test_conversion_from_python(self):
        # NOTE: 41 centiseconds = 410000 microseconds
        input = timedelta(days=2, hours=4, minutes=28, seconds=20,
                          microseconds=410000)
        result = t.TimeTicks(input)
        expected = t.TimeTicks(18890041)
        self.assertEqual(result, expected)

    def test_conversion_symmetry(self):
        input = timedelta(days=2, hours=4, minutes=28, seconds=20,
                          microseconds=410000)
        result = t.TimeTicks(input).pythonize()
        self.assertEqual(result, input)
