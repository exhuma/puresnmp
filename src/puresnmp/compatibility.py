"""
This file contains a compatibility layer for older Python versions which cause
issues with type-hinting and/or linting. Type-checks and linting is disabled as
needed in here.
"""

try:
    import importlib.metadata as importlib_metadata
except ModuleNotFoundError:
    import importlib_metadata  # type: ignore


def package_version(package_name: str) -> str:
    return importlib_metadata.version(package_name)
