"""
Helpers for the runtime environment puresnmp is installed in.
"""

from importlib.metadata import PackageNotFoundError, version


def package_version(package_name: str) -> str:
    """
    Return the installed version of *package_name*.

    Frozen applications (for example PyInstaller builds) may not bundle the
    package metadata. The placeholder ``0.0.0+unknown`` is returned then,
    instead of failing the import of :py:mod:`puresnmp`.

    :param package_name: The distribution name, e.g. ``"puresnmp"``.
    :returns: The installed version, or ``"0.0.0+unknown"``.
    """
    try:
        return version(package_name)
    except PackageNotFoundError:
        return "0.0.0+unknown"
