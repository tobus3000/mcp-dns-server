# Mixin Architecture for DNSMCPServer

## Overview

The `DNSMCPServer` class uses a **mixin pattern** to separate concerns and improve maintainability. Instead of having one monolithic 900+ line class, the functionality is split into four specialized mixin classes that each handle a specific responsibility.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│           DNSMCPServer (141 lines)                  │
│  - __init__()                                       │
│  - initialize_knowledge_base()                      │
│  - _register_all_components()                       │
│                                                     │
│  Inherits from:                                     │
│  ├── ToolRegistrationMixin                          │
│  ├── PromptRegistrationMixin                        │
│  ├── ResourceRegistrationMixin                      │
│  └── ServerLifecycleMixin                           │
└─────────────────────────────────────────────────────┘
         ↓                    ↓                    ↓
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ToolRegistration  │  │PromptRegistration│  │ResourceRegistration│
│      Mixin       │  │     Mixin        │  │     Mixin        │
│  (326 lines)     │  │  (501 lines)     │  │  (50 lines)      │
│                  │  │                  │  │                  │
│ Methods:         │  │ Methods:         │  │ Methods:         │
│ register_tools() │  │ register_tools   │  │ register_resolver│
│                  │  │ _prompts()       │  │ _resources()     │
│ Registers 24     │  │ register_knowledge│  │ register_knowledge│
│ DNS tools        │  │ _base_prompts()  │  │ _base_resources()│
│ (simple_dns      │  │                  │  │                  │
│  _lookup,        │  │ Registers 31     │  │ Registers DNS    │
│ advanced_dns     │  │ prompts:         │  │ resources:       │
│ _lookup,         │  │ - 28 tool        │  │ - root_servers   │
│ dns_trace,       │  │   guidance       │  │ - KB articles    │
│ mdns_service     │  │   prompts        │  │ - KB search      │
│ _discovery, etc) │  │ - 3 KB help      │  │ - KB categories  │
│                  │  │   prompts        │  │                  │
└──────────────────┘  └──────────────────┘  └──────────────────┘

         ↓
┌──────────────────────────────────┐
│  ServerLifecycleMixin            │
│  (8 lines + methods)             │
│                                  │
│ Methods:                         │
│ setup_signal_handlers()          │
│ _signal_handler()                │
│ start()                          │
│ stop()                           │
│                                  │
│ Manages:                         │
│ - Server startup                 │
│ - Signal handling                │
│ - Graceful shutdown              │
└──────────────────────────────────┘
```

## How It Works

### 1. **Initialization Flow**

```
DNSMCPServer.__init__()
    ↓
    ├─ Create self.server (FastMCP instance)
    ├─ Load self.config (YAML configuration)
    ├─ Create self.kb_manager (KnowledgeBase)
    ├─ Call _register_all_components()
    │   ├─ self.register_tools()           (from ToolRegistrationMixin)
    │   ├─ self.register_tools_prompts()   (from PromptRegistrationMixin)
    │   ├─ self.register_resolver_resources()  (from ResourceRegistrationMixin)
    │   └─ if KB enabled:
    │       ├─ self.register_knowledge_base_resources()  (from ResourceRegistrationMixin)
    │       └─ self.register_knowledge_base_prompts()    (from PromptRegistrationMixin)
    └─ Ready to start server
```

### 2. **Decorator Execution**

The key insight is that decorators execute **when the method is called**, not when the class is defined:

```python
# In server_mixins.py (Mixin definition)
class ToolRegistrationMixin:
    def register_tools(self):
        @self.server.tool(...)  # This decorator executes when register_tools() is CALLED
        async def simple_dns_lookup(...):
            ...

# In dns_mcp_server.py (DNSMCPServer.__init__)
self._register_all_components()  # <-- This calls register_tools()
  └─ self.register_tools()       # <-- HERE the decorators execute
      └─ @self.server.tool(...) is now executed
          └─ self.server is available!
```

### 3. **Method Resolution Order (MRO)**

When a method is called on a `DNSMCPServer` instance, Python searches for it using the MRO:

```
DNSMCPServer
  ↓ ToolRegistrationMixin
  ↓ PromptRegistrationMixin
  ↓ ResourceRegistrationMixin
  ↓ ServerLifecycleMixin
  ↓ object
```

So `self.server` and `self.config` defined in `DNSMCPServer.__init__()` are accessible to all mixin methods.

## Mixin Responsibilities

### ToolRegistrationMixin
- **Purpose**: Register DNS tools with the FastMCP server
- **Registers**: 24 DNS tools (lookup, trace, validation, scanning, etc.)
- **Dependencies**: Requires `self.server` and `self.config`
- **Line Count**: 326 lines

### PromptRegistrationMixin
- **Purpose**: Register prompts that guide tool usage
- **Registers**: 31 prompts total (28 tool guidance + 3 KB help)
- **Dependencies**: Requires `self.server` and `self.config`
- **Line Count**: 501 lines

### ResourceRegistrationMixin
- **Purpose**: Register DNS and knowledge base resources
- **Registers**: Root servers resource, KB article resources with CRUD
- **Dependencies**: Requires `self.server`, `self.config`, and `self.kb_manager`
- **Line Count**: 50 lines

### ServerLifecycleMixin
- **Purpose**: Manage server startup, shutdown, and signal handling
- **Provides**: Cross-platform signal handling, graceful shutdown
- **Dependencies**: Requires `self.server` and `self.logger`
- **Line Count**: 8 lines (plus implementation methods)

## Type Hints for Clarity

Each mixin class includes type hints for the attributes it expects from the host class:

```python
class ToolRegistrationMixin:
    """Mixin for registering DNS tools with the MCP server.

    Note: This mixin assumes the class has 'server' (FastMCP) and 'config' (dict)
    attributes available when register_tools() is called.
    """

    # Type hints for attributes provided by the host class
    server: Any  # FastMCP instance
    config: Dict[str, Any]  # Configuration dictionary
```

This clarifies what dependencies each mixin has without causing runtime errors.

## Benefits

✅ **Separation of Concerns**: Each mixin handles one specific responsibility
✅ **Improved Maintainability**: Easy to find and modify feature-specific code
✅ **Better Testability**: Mixins can be tested independently
✅ **Scalability**: Easy to add new tools, prompts, or resources
✅ **Code Organization**: 141-line main file vs. 943 lines before refactoring (85% reduction)
✅ **No Functionality Lost**: All 24 tools and 31 prompts work exactly as before

## File Structure

```
src/
├── dns_mcp_server.py          # Main DNSMCPServer class (141 lines)
│   └── Inherits from 4 mixins
├── server_mixins.py           # All mixin classes (886 lines total)
│   ├── ToolRegistrationMixin
│   ├── PromptRegistrationMixin
│   ├── ResourceRegistrationMixin
│   └── ServerLifecycleMixin
└── tools/                      # Tool implementations
    ├── __init__.py           # Exports implementation functions
    ├── converter.py
    ├── dns/
    ├── mdns/
    ├── scanner/
    ├── validator/
    └── assistant/
```

## Running the Server

The server still starts the same way:

```python
from dns_mcp_server import DNSMCPServer

server = DNSMCPServer()
await server.start()
```

The `__init__()` method automatically:
1. Creates the FastMCP server instance
2. Loads configuration
3. Initializes the knowledge base
4. **Calls `_register_all_components()`** which triggers all mixin registration methods
5. Returns a fully configured server ready to start

## Lint Notes

Type checkers may report that mixin classes don't have `server`, `config`, etc., but these are false positives. The attributes are provided by the `DNSMCPServer` class at runtime through multiple inheritance. The type hints in each mixin clarify this relationship.
