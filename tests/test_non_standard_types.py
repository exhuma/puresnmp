# pylint: skip-file

from datetime import timedelta
from ipaddress import ip_address

from puresnmp import types as t

from . import ByteTester


class TestIpAddress(ByteTester):
    def test_decoding(self):
        result = t.IpAddress.decode_raw(b"\xc0\x00\x02\x01")
        expected = ip_address("192.0.2.1")
        self.assertEqual(result, expected)

    def test_encoding(self):
        value = t.IpAddress(ip_address("192.0.2.1"))
        result = bytes(value)
        expected = b"\x40\x04\xc0\x00\x02\x01"
        self.assertBytesEqual(result, expected)

    def test_conversion_symmetry(self):
        input = ip_address("192.0.2.1")
        result = t.IpAddress(input).pythonize()
        self.assertEqual(result, input)


class TestTimeTicks(ByteTester):
    def test_decoding(self):
        result = t.TimeTicks.decode_raw(b"\x0a")
        expected = 10
        self.assertEqual(result, expected)

    def test_encoding(self):
        value = t.TimeTicks(100)
        result = bytes(value)
        expected = b"\x43\x01\x64"
        self.assertBytesEqual(result, expected)

    def test_conversion_to_python(self):
        # NOTE: 41 centiseconds = 410000 microseconds
        result = t.TimeTicks(18890041).pythonize()
        expected = timedelta(
            days=2, hours=4, minutes=28, seconds=20, microseconds=410000
        )
        self.assertEqual(result, expected)

    def test_conversion_from_python(self):
        # NOTE: 41 centiseconds = 410000 microseconds
        input = timedelta(
            days=2, hours=4, minutes=28, seconds=20, microseconds=410000
        )
        result = t.TimeTicks(input)
        expected = t.TimeTicks(18890041)
        self.assertEqual(result, expected)

    def test_conversion_symmetry(self):
        input = timedelta(
            days=2, hours=4, minutes=28, seconds=20, microseconds=410000
        )
        result = t.TimeTicks(input).pythonize()
        self.assertEqual(result, input)
