# MCP DNS Server

An MCP (Model Context Protocol) server designed to assist with DNS name resolution and advanced DNS troubleshooting scenarios.

## Features

- Simple DNS name resolution
- Advanced DNS troubleshooting capabilities
- Integration with fastmcp library
- Configurable DNS server settings
- Support for multiple DNS record types

## Prerequisites

- Python 3.8+
- Install using pip with pyproject.toml

## Installation

```bash
pip install .
# or for development:
pip install -e .
```

## Usage

```bash
python -m src.dns_mcp_server
# or using the installed script:
mcp-dns-server
```

## Configuration

The server can be configured via the `config/config.yaml` file.

## Todo

- TODO: IoT DNS server inspection.
- TODO: Environment check - Internal or Internet root server detection
- TODO: Environment check - Check root server types. IANA root, other roots, or internal root?
- TODO: Feature flag for AXFR checks.
