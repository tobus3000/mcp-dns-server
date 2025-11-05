# MCP DNS Server Documentation

## Overview

The MCP DNS Server is an implementation of the Model Context Protocol (MCP) that provides DNS resolution and troubleshooting capabilities. It allows AI models and other applications to perform various DNS operations through standardized tool calls.

## Features

### Simple DNS Lookup
- Resolve hostnames to IP addresses (A records)
- Supports both IPv4 and IPv6 addresses

### Advanced DNS Lookup
- Support for multiple DNS record types:
  - A: IPv4 address records
  - AAAA: IPv6 address records
  - CNAME: Canonical name records
  - MX: Mail exchange records
  - NS: Name server records
  - TXT: Text records
  - PTR: Pointer records (reverse DNS)
  - SOA: Start of authority records
  - SRV: Service records

### Reverse DNS Lookup
- Convert IP addresses to hostnames using PTR records

### DNS Troubleshooting
- Comprehensive diagnostic tool that checks multiple record types for a domain
- Provides detailed information about DNS configuration

### Knowledge Base
- Built-in knowledge base with articles on DNS configurations and troubleshooting
- Articles are stored in YAML format for easy maintenance
- Articles can be accessed directly or through search functionality
- Knowledge base includes information on:
  - DNS Extranet setup
  - Troubleshooting common issues
  - Security best practices

## Installation

1. Clone or download the repository
2. Install the package: `pip install .`
   - For development: `pip install -e .`
3. (Optional) Modify `config/config.yaml` to customize DNS settings

## Configuration

The server can be configured via the `config/config.yaml` file:

```yaml
server:
  host: "127.0.0.1"  # Host to bind to
  port: 3000          # Port to listen on

dns:
  # Custom DNS servers to use (optional)
  # dns_servers:
  #   - "8.8.8.8"
  #   - "8.8.4.4"

  # Timeout for DNS queries in seconds
  timeout: 5

  # Number of retries for failed DNS queries
  retries: 2

features:
  # Enable advanced DNS troubleshooting
  advanced_troubleshooting: true

  # Enable reverse DNS lookups
  reverse_lookup: true
```

## Usage

### Running the Server

After installation, you can run the server in two ways:

Direct execution:
```bash
python launch.py
```

Or using the installed script (after `pip install .`):
```bash
mcp-dns-server
```

The server will start and listen for MCP connections on the configured host and port.

### Available Tools

#### `simple_dns_lookup`
Perform a simple DNS lookup for a hostname to get its IP address.

Parameters:
- `hostname` (string): The hostname to resolve

Example:
```json
{
  "hostname": "example.com"
}
```

#### `advanced_dns_lookup`
Perform an advanced DNS lookup supporting multiple record types.

Parameters:
- `hostname` (string): The hostname to resolve
- `record_type` (string): DNS record type to query (A, AAAA, CNAME, MX, NS, TXT, PTR, SOA, SRV)

Example:
```json
{
  "hostname": "example.com",
  "record_type": "MX"
}
```

#### `reverse_dns_lookup`
Perform a reverse DNS lookup to get hostname from IP address.

Parameters:
- `ip_address` (string): The IP address to reverse lookup

Example:
```json
{
  "ip_address": "8.8.8.8"
}
```

#### `dns_troubleshooting`
Perform comprehensive DNS troubleshooting for a given domain.

Parameters:
- `domain` (string): The domain to troubleshoot

Example:
```json
{
  "domain": "example.com"
}
```

## Knowledge Base Resources

The MCP DNS Server also provides several resources to access its built-in knowledge base:

#### `dns_knowledge_base_article`
Provides access to a specific DNS knowledge base article by ID.

Parameters:
- `article_id` (string): The ID of the knowledge base article to retrieve

Example:
```json
{
  "article_id": "dns_extranet_setup"
}
```

#### `dns_knowledge_base_search`
Search the DNS knowledge base for articles matching a query.

Parameters:
- `query` (string): Search query to match in article titles, content, or tags

Example:
```json
{
  "query": "troubleshooting"
}
```

#### `dns_knowledge_base_categories`
Get all available categories in the DNS knowledge base.

Parameters: None

Example: No parameters needed

#### `dns_knowledge_base_by_category`
Get DNS knowledge base articles by category.

Parameters:
- `category` (string): The category to filter articles by

Example:
```json
{
  "category": "troubleshooting"
}
```

## Integration with AI Models

The MCP DNS Server can be integrated with AI models that support the Model Context Protocol. The server exposes DNS functionality through standardized tool calls that the AI can invoke when it needs to resolve domain names or troubleshoot DNS issues.

## Knowledge Base Prompts

The server provides several built-in prompts to help AI models interact effectively with the knowledge base:

- `dns_troubleshooting_help`: Get assistance with DNS troubleshooting using the knowledge base
- `dns_configuration_help`: Get assistance with DNS configuration using the knowledge base
- `dns_security_help`: Get assistance with DNS security best practices using the knowledge base

## Troubleshooting

- If the server fails to start, check that the configured port is not already in use
- If DNS lookups fail, verify your network connectivity and DNS server configuration
- Check the server logs for error messages if operations are failing
