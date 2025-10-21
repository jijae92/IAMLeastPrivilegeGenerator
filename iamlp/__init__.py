"""Namespace package re-exporting project modules."""

from importlib import import_module

__all__ = ["cli", "core", "apiserver"]


def __getattr__(name: str):  # pragma: no cover - delegation helper
    if name in __all__:
        return import_module(name)
    raise AttributeError(f"module 'iamlp' has no attribute {name}")


__version__ = "0.1.0"
