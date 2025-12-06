"""Launch script for the MCP DNS Server.

This can be used as:
- Direct execution: python launch.py
- Docker entrypoint: ENTRYPOINT ["python", "launch.py"]
- Package CLI: mcp-dns-server (after installation)
"""

import os
import sys

# Add src directory to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from dns_mcp_server import run_server

if __name__ == "__main__":
    run_server()
