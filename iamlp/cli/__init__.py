"""CLI forwarding module to allow `python -m iamlp.cli`."""

from cli.main import app, build_parser, main

__all__ = ["app", "build_parser", "main"]
