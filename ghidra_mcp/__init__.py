"""
GhidraMCP - MCP bridge for Ghidra reverse engineering.

This package provides an MCP (Model Context Protocol) server that bridges
Claude and other LLM agents to Ghidra for automated reverse engineering.

Usage:
    python -m ghidra_mcp --ghidra-server http://127.0.0.1:8080/

Package Structure:
    core        - MCP instance, HTTP helpers, health check
    listing     - Function/class/import/export listing
    decompile   - Decompilation and disassembly
    navigation  - Cursor and address navigation
    modification- Renaming and comment tools
    xrefs       - Cross-references and call graphs
    memory      - Memory read/write/search
    types/      - Structure, enum, and data type management
    analysis/   - Statistics, vtables, and pattern inference
    batch       - Batch rename and comment operations
    workflow    - Agent workflow optimization tools
    rtti        - RTTI extraction and analysis
    export      - C header export for SDK generation
    bookmarks   - Bookmark and equate management
    efficiency  - High-efficiency tools, parallel workers, session management
"""

# Import core components first
from .core import mcp, safe_get, safe_post, set_server_url, ghidra_server_url

# Import all modules to register their @mcp.tool() decorators
# Order doesn't matter since decorators register on import
from . import listing
from . import decompile
from . import navigation
from . import modification
from . import xrefs
from . import memory
from . import batch
from . import workflow
from . import rtti
from . import export
from . import bookmarks
from . import efficiency

# Import subpackages
from . import types
from . import analysis

__version__ = "1.0.0"
__all__ = [
    'mcp',
    'safe_get',
    'safe_post',
    'set_server_url',
    'ghidra_server_url',
]
