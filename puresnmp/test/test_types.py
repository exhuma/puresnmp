"""
Unit tests for types specified in RFC-2578
"""

import pytest
from puresnmp import types as t


@pytest.mark.parametrize('value, expected', [
    (-42, 0),  # Underflow below threshold
    (-1, 0),  # Underflow at threshold
    (0, 0),  # The minimum value
    (42, 42),  # A normal value
    (2**32-1, 2**32-1),  # max value
    (2**32, 0),  # overflow at threshold
    (2**32+42, 42),  # overflow above threshold
    ((2**32)*2+42, 42),  # overflow above threshold
])
def test_counter(value, expected):
    """
    A counter instance should be a non-negative integer
    """
    instance = t.Counter(value)
    assert instance.value == expected


@pytest.mark.parametrize('value, expected', [
    (-42, 0),  # Underflow below threshold
    (-1, 0),  # Underflow at threshold
    (0, 0),  # The minimum value
    (42, 42),  # A normal value
    (2**64-1, 2**64-1),  # max value
    (2**64, 0),  # overflow at threshold
    ((2**64)*2+42, 42),  # overflow above threshold
])
def test_counter64(value, expected):
    """
    A counter instance should be a non-negative integer
    """
    instance = t.Counter64(value)
    assert instance.value == expected
