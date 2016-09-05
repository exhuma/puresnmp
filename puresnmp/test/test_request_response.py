import unittest

from ..x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
)
from ..types import (
    GetResponse,
    VarBind,
)

from . import readbytes
from ..const import Version


class TestResponses(unittest.TestCase):

    def test_get_sysdescr_01(self):
        data = readbytes('get_sysdescr_01.hex')
        result = Sequence.from_bytes(data)
        expected = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            GetResponse(
                Integer(3262242864),  # request-id
                [VarBind(
                    ObjectIdentifier.from_string('1.3.6.1.2.1.1.1.0'),
                    OctetString('Linux d24cf7f36138 4.4.0-28-generic '
                                '#47-Ubuntu SMP Fri Jun 24 10:09:13 UTC 2016 '
                                'x86_64')
                )]
            )
        )
        self.assertEqual(result, expected)
