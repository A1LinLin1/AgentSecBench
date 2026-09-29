"""Allow ``python -m agentsecbench`` to behave like the console command."""

from __future__ import annotations

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
