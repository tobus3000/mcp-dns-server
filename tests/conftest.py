"""Configuration for pytest."""

import os
import sys

# Add the src directory to the Python path to enable proper module resolution
# This handles both local development and CI environments
test_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(test_dir)
src_dir = os.path.join(project_root, "src/dns_mcp_server")

# Insert src directory at the beginning of sys.path if not already present
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Also ensure the project root is available for any packages that need it
if project_root not in sys.path:
    sys.path.insert(0, project_root)
