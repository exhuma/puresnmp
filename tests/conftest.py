"""
Global configuration for pytest
"""
from itertools import zip_longest
from typing import Any, List
from unittest.mock import call

import pytest
from x690.util import visible_octets


class AsyncIter:
    def __init__(self, values):
        self.values = values

    async def __aiter__(self):
        for value in self.values:
            yield value


class FakeSend:
    def __init__(self):
        self.iter = iter([])
        self.mock_calls = []

    async def __call__(self, *args, **kwargs) -> Any:
        self.mock_calls.append(call(*args, **kwargs))
        return next(self.iter)

    def set_values(self, values):
        self.iter = iter(values)


@pytest.fixture
def mocked_raw():
    from puresnmp import Client
    from puresnmp.credentials import V2C

    sender = FakeSend()
    client = Client("192.0.2.1", V2C("private"), sender=sender)
    yield client


def get_byte_diff(a: bytes, b: bytes) -> List[str]:
    comparisons = []
    a = bytearray(a)
    b = bytearray(b)

    def char_repr(c: int) -> str:
        if 0x1F < c < 0x80:
            # bytearray to prevent accidental pre-mature str conv
            # str to prevent b'' suffix in repr's output
            return repr(str(bytearray([c]).decode("ascii")))
        return "."

    hexdump_a = visible_octets(a).splitlines()
    hexdump_b = visible_octets(b).splitlines()
    hexdiff = zip_longest(hexdump_a, hexdump_b)
    comparisons.append(" Hex Dumps ".center(141, "-"))
    comparisons.extend(
        [
            "%s   %s   %s" % (left, " " if left == right else "≠", right)
            for left, right in hexdiff
        ]
    )
    comparisons.append(141 * "-")

    for offset, (char_a, char_b) in enumerate(zip_longest(a, b)):
        comp, marker = ("==", "") if char_a == char_b else ("!=", ">>")

        # Using "zip_longest", overflows are marked as "None", which is
        # unambiguous in this case, but we need to handle these
        # separately from the main format string.
        if char_a is None:
            char_ab = char_ad = char_ah = char_ar = "?"
        else:
            char_ab = f"0b{char_a:08b}"
            char_ad = f"{char_a:3d}"
            char_ah = f"0x{char_a:02x}"
            char_ar = char_repr(char_a)

        if char_b is None:
            char_bb = char_bd = char_bh = char_br = "?"
        else:
            char_bb = f"0b{char_b:08b}"
            char_bd = f"{char_b:3d}"
            char_bh = f"0x{char_b:02x}"
            char_br = char_repr(char_b)
        comparisons.append(
            "{8:<3} Offset {0:4d}: "
            "{1:^10} {4} {5:^10} | "
            "{2:>3} {4} {6:>3} | "
            "{3:^4} {4} {7:^4} | {9:>3} {4} {10:>3}".format(
                offset,
                char_ab,
                char_ad,
                char_ah,
                comp,
                char_bb,
                char_bd,
                char_bh,
                marker,
                char_ar,
                char_br,
            )
        )
    return comparisons


def pytest_assertrepr_compare(op, left, right):
    if isinstance(left, bytes) and isinstance(right, bytes) and op == "==":
        output = ["Bytes differ"]
        output.extend(get_byte_diff(left, right))
        return output
