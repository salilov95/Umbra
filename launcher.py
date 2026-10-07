"""Entry point for PyInstaller (a package's __main__ cannot be frozen directly)."""
import sys

from umbra.app import main

sys.exit(main())
