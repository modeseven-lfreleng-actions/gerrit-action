# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Pytest configuration for Gerrit API tests."""

from __future__ import annotations

import sys
from pathlib import Path

# Add the scripts/lib directory to the path for imports
SCRIPTS_LIB_DIR = Path(__file__).parent.parent / "scripts" / "lib"
sys.path.insert(0, str(SCRIPTS_LIB_DIR))
