"""Module entrypoint for `python -m password_manager`."""

from .cli import run


if __name__ == "__main__":
    raise SystemExit(run())
