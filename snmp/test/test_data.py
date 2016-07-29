from os.path import dirname, join
import unittest

from ..x690.types import (
    GetResponse,
    Integer,
    Sequence,
    String,
)

from ..const import Version


DATA_DIR = join(dirname(__file__), 'data')


def readbytes(filename):
    with open(join(DATA_DIR, filename)) as fp:
        lines = fp.readlines()
    without_ascii = [line[:50] for line in lines]
    str_bytes = []
    for line in without_ascii:
        str_bytes.extend(line.split())
    values = [int(char, 16) for char in str_bytes]
    return bytes(values)


class TestResponses(unittest.TestCase):

    def test_get_sysdescr_01(self):
        data = readbytes('get_sysdescr_01.hex')
        result = Sequence.from_bytes(data)
        expected = Sequence(
            Integer(Version.V2C),
            String('public'),
            GetResponse(
                Integer(3262242864),  # request-id
                String('Linux d24cf7f36138 4.4.0-28-generic #47-Ubuntu SMP '
                       'Fri Jun 24 10:09:13 UTC 2016 x86_64')
            )
        )
        self.assertEqual(result, expected)
