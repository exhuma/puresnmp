# pylint: skip-file
from __future__ import unicode_literals

from datetime import timedelta
from ipaddress import ip_address

from . import ByteTester
from .. import types as t
from ..x690.util import to_bytes


class TestIpAddress(ByteTester):

    def test_decoding(self):
        result = t.IpAddress.from_bytes(b'\x40\x04\x80\x96\xa1\x09')
        expected = t.IpAddress(b'\x80\x96\xa1\x09')
        self.assertEqual(result, expected)

    def test_encoding(self):
        value = t.IpAddress(b'\x80\x96\xa1\x09')
        result = to_bytes(value)
        expected = b'\x40\x04\x80\x96\xa1\x09'
        self.assertBytesEqual(result, expected)

    def test_conversion_to_python(self):
        result = t.IpAddress(b'\x80\x96\xa1\x09').pythonize()
        expected = b'\x80\x96\xa1\x09'
        # TODO 2.0.0 expected = ip_address('128.150.161.9')
        self.assertEqual(result, expected)

    def test_conversion_from_python(self):
        input = ip_address('128.150.161.9')
        result = t.IpAddress(input)
        expected = t.IpAddress(b'\x80\x96\xa1\x09')
        self.assertEqual(result, expected)

    def test_conversion_symmetry(self):
        input = b'\x80\x96\xa1\t'
        # TODO 2.0.0 input = ip_address('128.150.161.9')
        result = t.IpAddress(input).pythonize()
        self.assertEqual(result, input)


class TestTimeTicks(ByteTester):

    def test_decoding(self):
        result = t.TimeTicks.from_bytes(b'\x43\x01\x0a')
        expected = t.TimeTicks(10)
        self.assertEqual(result, expected)

    def test_encoding(self):
        value = t.TimeTicks(100)
        result = to_bytes(value)
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
