"""Allows `python -m ctfc ...` to work without installing the package."""

from ctfc.cli import main

raise SystemExit(main())
