"""
Global configuration for pytest
"""
from typing import Any
from unittest.mock import call

import pytest

from puresnmp.api.raw import RawClient
from puresnmp.credentials import V2C

collect_ignore = [
    "test_aio_pythonized.py",
    "test_aio_raw.py",
]


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
def mocked_send():
    sender = FakeSend()
    client = RawClient("192.0.2.1", V2C("private"), sender=sender)
    yield client
