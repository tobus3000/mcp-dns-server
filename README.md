# MCP DNS Server

[![CI](https://github.com/tobus3000/mcp-dns-server/actions/workflows/python-package.yml/badge.svg)](https://github.com/tobus3000/mcp-dns-server/actions)
[![codecov](https://codecov.io/gh/tobus3000/mcp-dns-server/graph/badge.svg?token=0H8USNAAJ0)](https://codecov.io/gh/tobus3000/mcp-dns-server)

An MCP (Model Context Protocol) server designed to assist with DNS name resolution and advanced DNS troubleshooting scenarios.

## Features

- Simple DNS name resolution
- Advanced DNS troubleshooting capabilities
- Integration with fastmcp library
- Configurable DNS server settings
- Support for multiple DNS record types

## Prerequisites

- Python 3.11+
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

- TODO: Feature flag for AXFR checks.
