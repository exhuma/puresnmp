# pylint: skip-file
# type: ignore


try:
    from unittest.mock import MagicMock
except ImportError:
    from unittest.mock import MagicMock  # type: ignore


class AsyncMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        return super().__call__(*args, **kwargs)


class AsyncGenMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        for item in super().__call__(*args, **kwargs):
            yield item
