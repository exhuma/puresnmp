"""
Tests for the version lookup helper in :mod:`puresnmp.compatibility`.

Frozen applications (for example PyInstaller bundles) may ship without the
package metadata, so the lookup must degrade to a fallback instead of
failing the import of :mod:`puresnmp`.
"""

import importlib.metadata
import pytest

import puresnmp.compatibility
from puresnmp.compatibility import package_version


def test_missing_metadata_returns_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Ensure a missing package metadata lookup returns the fallback version.
    """

    def _raise(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(puresnmp.compatibility, "version", _raise)
    assert package_version("puresnmp") == "0.0.0+unknown"


def test_installed_package_returns_real_version() -> None:
    """
    Ensure the helper returns the installed version when metadata exists.
    """
    version = package_version("puresnmp")
    assert isinstance(version, str)
    assert version
    assert version != "0.0.0+unknown"
