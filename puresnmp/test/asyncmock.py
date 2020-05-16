# pylint: skip-file
# type: ignore


try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock  # type: ignore


class AsyncMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        return super(AsyncMock, self).__call__(*args, **kwargs)


class AsyncGenMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        for item in super(AsyncGenMock, self).__call__(*args, **kwargs):
            yield item
