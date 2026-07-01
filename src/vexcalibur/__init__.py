"""Vexcalibur package."""

try:
    from vexcalibur._version import __version__
except ImportError:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _distribution_version

    try:
        __version__ = _distribution_version("vexcalibur")
    except PackageNotFoundError:
        __version__ = "unknown"

__all__ = ["__version__"]
