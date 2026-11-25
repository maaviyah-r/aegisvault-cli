"""Allow invoking the CLI via `python -m aegisvault`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
