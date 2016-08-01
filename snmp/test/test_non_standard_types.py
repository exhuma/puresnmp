from . import ByteTester

from ..x690 import types as t


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
