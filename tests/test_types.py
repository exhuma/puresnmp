"""
Unit tests for types specified in RFC-2578
"""

from typing import Any, Type

import pytest
import x690

from puresnmp import types as t
from puresnmp.pdu import EndOfMibView, NoSuchInstance, NoSuchObject


@pytest.mark.parametrize(
    "value, expected",
    [
        (-42, 0),  # Underflow below threshold
        (-1, 0),  # Underflow at threshold
        (0, 0),  # The minimum value
        (42, 42),  # A normal value
        (2 ** 32 - 1, 2 ** 32 - 1),  # max value
        (2 ** 32, 0),  # overflow at threshold
        (2 ** 32 + 42, 42),  # overflow above threshold
        ((2 ** 32) * 2 + 42, 42),  # overflow above threshold
    ],
)
def test_counter(value, expected):
    """
    A counter instance should be a non-negative integer
    """
    instance = t.Counter(value)
    assert instance.value == expected


def test_counter_issue_75():
    """
    GitHub issue #75 reports incorrect counter decoding.

    This test covers this issue.
    """
    data = b"\x41\x04\x84\x43\x20\xf8"
    result = t.Counter.decode(data)
    expected = t.Counter(2218991864)
    assert result == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (-42, 0),  # Underflow below threshold
        (-1, 0),  # Underflow at threshold
        (0, 0),  # The minimum value
        (42, 42),  # A normal value
        (2 ** 64 - 1, 2 ** 64 - 1),  # max value
        (2 ** 64, 0),  # overflow at threshold
        ((2 ** 64) * 2 + 42, 42),  # overflow above threshold
    ],
)
def test_counter64(value, expected):
    """
    A counter instance should be a non-negative integer
    """
    instance = t.Counter64(value)
    assert instance.value == expected


@pytest.mark.parametrize("cls", [NoSuchObject, NoSuchInstance, EndOfMibView])
def test_nullish_types(cls: Type[x690.types.Type[Any]]) -> None:
    """
    SNMP types which indicate the non-existance of values should be None in
    the python-world
    """
    instance = cls()
    assert instance.pythonize() is None
