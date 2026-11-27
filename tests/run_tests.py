#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Abdulrahman Almuhairi
"""GRAFT test runner — stdlib unittest only. Exit non-zero on any failure."""
import sys, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent

def main():
    suite = unittest.defaultTestLoader.discover(str(HERE), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1

if __name__ == "__main__":
    sys.exit(main())