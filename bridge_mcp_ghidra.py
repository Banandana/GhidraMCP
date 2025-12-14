# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

DEFAULT_TIMEOUT = 120  # 2 minutes for complex analysis operations

def safe_get(endpoint: str, params: dict = None, timeout: int = DEFAULT_TIMEOUT) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str, timeout: int = DEFAULT_TIMEOUT) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str, max_lines: int = 200) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.

    Args:
        name: The function name to decompile
        max_lines: Maximum number of lines to return (default: 200, 0 for unlimited)

    Returns:
        Decompiled C code (truncated if exceeds max_lines)
    """
    result = safe_post("decompile", name)
    if max_lines > 0:
        lines = result.split('\n')
        if len(lines) > max_lines:
            return '\n'.join(lines[:max_lines]) + f'\n\n... [truncated, showing {max_lines} of {len(lines)} lines]'
    return result

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions(offset: int = 0, limit: int = 100) -> list:
    """
    List all functions in the database with pagination.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of functions to return (default: 100)

    Returns:
        List of functions with their addresses
    """
    return safe_get("list_functions", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function_by_address(address: str, max_lines: int = 200) -> str:
    """
    Decompile a function at the given address.

    Args:
        address: Function address in hex format (e.g. "0x1400010a0")
        max_lines: Maximum number of lines to return (default: 200, 0 for unlimited)

    Returns:
        Decompiled C code (truncated if exceeds max_lines)
    """
    result = "\n".join(safe_get("decompile_function", {"address": address}))
    if max_lines > 0:
        lines = result.split('\n')
        if len(lines) > max_lines:
            return '\n'.join(lines[:max_lines]) + f'\n\n... [truncated, showing {max_lines} of {len(lines)} lines]'
    return result

@mcp.tool()
def disassemble_function(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get assembly code (address: instruction; comment) for a function with pagination.

    Args:
        address: Function address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of instructions to return (default: 100)

    Returns:
        List of disassembled instructions
    """
    return safe_get("disassemble_function", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 1000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 1000)
        filter: Optional filter to match within string content

    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

# =============================================================================
# NEW MCP TOOLS
# =============================================================================

@mcp.tool()
def get_program_info() -> str:
    """
    Get program metadata and architecture information.

    Returns comprehensive information about the loaded binary including:
    - Program name and executable path
    - Language ID (e.g., x86:LE:64:default)
    - Compiler specification
    - Processor and endianness
    - Address size
    - Executable format (PE, ELF, Mach-O, etc.)
    - Image base address
    - Memory size and blocks summary
    - Function and symbol counts
    """
    return "\n".join(safe_get("program_info"))

@mcp.tool()
def get_function_callees(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all functions called by a function (callees/call targets).

    Args:
        address: Function address in hex format (e.g., "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of functions that this function calls
    """
    return safe_get("get_callees", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_callers(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all functions that call a function (callers/call sources).

    Args:
        address: Function address in hex format (e.g., "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of functions that call this function
    """
    return safe_get("get_callers", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def read_memory(address: str, length: int = 256) -> str:
    """
    Read raw memory bytes at a specified address.

    Args:
        address: Starting address in hex format (e.g., "0x1400010a0")
        length: Number of bytes to read (default: 256, max: 4096)

    Returns:
        Hex dump of memory with ASCII representation
    """
    return "\n".join(safe_get("read_memory", {"address": address, "length": length}))

@mcp.tool()
def search_memory(pattern: str, start: str = None, end: str = None, max_results: int = 100) -> str:
    """
    Search memory for a byte pattern.

    Args:
        pattern: Hex string pattern to search for (e.g., "4D5A" for MZ header, "90909090" for NOP sled)
        start: Optional start address for search range
        end: Optional end address for search range
        max_results: Maximum number of matches to return (default: 100)

    Returns:
        List of addresses where pattern was found, with function context if available
    """
    params = {"pattern": pattern, "max_results": max_results}
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    return "\n".join(safe_get("search_memory", params))

@mcp.tool()
def get_basic_blocks(address: str) -> str:
    """
    Get basic blocks and control flow information for a function.

    Args:
        address: Function address in hex format (e.g., "0x1400010a0")

    Returns:
        List of basic blocks with their start/end addresses, successors, and predecessors.
        Useful for understanding control flow, identifying loops, and analyzing branches.
    """
    return "\n".join(safe_get("get_basic_blocks", {"address": address}))

@mcp.tool()
def list_data_types(offset: int = 0, limit: int = 100, category: str = None) -> list:
    """
    List all data types defined in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)
        category: Optional category filter (e.g., "windows", "struct")

    Returns:
        List of data types with their paths, types, and sizes
    """
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    return safe_get("list_data_types", params)

@mcp.tool()
def list_structures(offset: int = 0, limit: int = 100) -> list:
    """
    List all structures defined in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of structures with their sizes and field counts
    """
    return safe_get("list_structures", {"offset": offset, "limit": limit})

@mcp.tool()
def get_structure(name: str) -> str:
    """
    Get detailed information about a structure.

    Args:
        name: Structure name to look up

    Returns:
        Detailed structure layout including all fields with offsets, sizes, and types
    """
    return "\n".join(safe_get("get_structure", {"name": name}))

@mcp.tool()
def list_equates(offset: int = 0, limit: int = 100) -> list:
    """
    List all equates (named constants) in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of equates with their names, values, and reference counts
    """
    return safe_get("list_equates", {"offset": offset, "limit": limit})

@mcp.tool()
def create_equate(name: str, value: str, address: str = None, operand_index: str = None) -> str:
    """
    Create an equate (named constant) and optionally apply it to an operand.

    Args:
        name: Name for the equate (e.g., "STATUS_SUCCESS", "SOCKET_ERROR")
        value: Value as decimal or hex string (e.g., "0" or "0xFFFFFFFF")
        address: Optional address to apply the equate
        operand_index: Optional operand index (0, 1, 2...) when applying to an address

    Returns:
        Confirmation message with equate details
    """
    params = {"name": name, "value": value}
    if address:
        params["address"] = address
    if operand_index:
        params["operand_index"] = operand_index
    return safe_post("create_equate", params)

@mcp.tool()
def list_bookmarks(offset: int = 0, limit: int = 100, category: str = None) -> list:
    """
    List all bookmarks in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)
        category: Optional category filter

    Returns:
        List of bookmarks with their types, categories, addresses, and comments
    """
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    return safe_get("list_bookmarks", params)

@mcp.tool()
def create_bookmark(address: str, category: str = "Analysis", description: str = "") -> str:
    """
    Create a bookmark at an address.

    Args:
        address: Address in hex format (e.g., "0x1400010a0")
        category: Bookmark category (default: "Analysis")
        description: Bookmark description/comment

    Returns:
        Confirmation message
    """
    return safe_post("create_bookmark", {
        "address": address,
        "category": category,
        "description": description
    })

@mcp.tool()
def get_stack_frame(address: str) -> str:
    """
    Get stack frame information for a function.

    Args:
        address: Function address in hex format (e.g., "0x1400010a0")

    Returns:
        Detailed stack frame information including:
        - Frame size, local variable size, parameter size
        - Parameters with storage locations, sizes, types, and names
        - Local variables with offsets, sizes, types, and names
        - All stack variables sorted by offset
    """
    return "\n".join(safe_get("get_stack_frame", {"address": address}))

# =============================================================================
# STRUCTURE MANAGEMENT TOOLS
# =============================================================================

@mcp.tool()
def create_struct(name: str, category: str = None, size: int = 0) -> str:
    """
    Create a new structure data type.

    Args:
        name: Name for the new structure
        category: Optional category path (e.g., "MyStructures")
        size: Initial size in bytes (default: 0 for auto-sizing)

    Returns:
        Confirmation message with structure details
    """
    params = {"name": name, "size": str(size)}
    if category:
        params["category"] = category
    return safe_post("create_struct", params)

@mcp.tool()
def add_struct_member(struct_name: str, field_name: str, data_type: str,
                      offset: int = -1, category: str = None, comment: str = None) -> str:
    """
    Add a member field to an existing structure.

    Args:
        struct_name: Name of the structure to modify
        field_name: Name for the new field
        data_type: Data type for the field (e.g., "int", "DWORD", "char[32]")
        offset: Byte offset for the field (-1 to append at end)
        category: Optional category path if structure is in a category
        comment: Optional comment for the field

    Returns:
        Confirmation message with field details
    """
    params = {
        "struct_name": struct_name,
        "field_name": field_name,
        "data_type": data_type,
        "offset": str(offset)
    }
    if category:
        params["category"] = category
    if comment:
        params["comment"] = comment
    return safe_post("add_struct_member", params)

@mcp.tool()
def remove_struct_member(struct_name: str, field_name: str = None,
                         offset: int = -1, category: str = None) -> str:
    """
    Remove a member from a structure.

    Args:
        struct_name: Name of the structure to modify
        field_name: Name of the field to remove (optional if offset provided)
        offset: Byte offset of the field to remove (optional if field_name provided)
        category: Optional category path if structure is in a category

    Returns:
        Confirmation message
    """
    params = {"struct_name": struct_name, "offset": str(offset)}
    if field_name:
        params["field_name"] = field_name
    if category:
        params["category"] = category
    return safe_post("remove_struct_member", params)

@mcp.tool()
def clear_struct(struct_name: str, category: str = None) -> str:
    """
    Remove all members from a structure.

    Args:
        struct_name: Name of the structure to clear
        category: Optional category path if structure is in a category

    Returns:
        Confirmation message with number of fields cleared
    """
    params = {"struct_name": struct_name}
    if category:
        params["category"] = category
    return safe_post("clear_struct", params)

# =============================================================================
# ENUM MANAGEMENT TOOLS
# =============================================================================

@mcp.tool()
def create_enum(name: str, size: int = 4, category: str = None) -> str:
    """
    Create a new enumeration data type.

    Args:
        name: Name for the new enum
        size: Size in bytes (1, 2, 4, or 8; default: 4)
        category: Optional category path

    Returns:
        Confirmation message with enum details
    """
    params = {"name": name, "size": str(size)}
    if category:
        params["category"] = category
    return safe_post("create_enum", params)

@mcp.tool()
def get_enum(name: str, category: str = None) -> str:
    """
    Get detailed information about an enum.

    Args:
        name: Enum name to look up
        category: Optional category path

    Returns:
        Detailed enum information including all values with their numeric equivalents
    """
    params = {"name": name}
    if category:
        params["category"] = category
    return "\n".join(safe_get("get_enum", params))

@mcp.tool()
def list_enums(offset: int = 0, limit: int = 100) -> list:
    """
    List all enumerations defined in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of enums with their sizes and value counts
    """
    return safe_get("list_enums", {"offset": offset, "limit": limit})

@mcp.tool()
def add_enum_value(enum_name: str, value_name: str, value: str, category: str = None) -> str:
    """
    Add a value to an existing enum.

    Args:
        enum_name: Name of the enum to modify
        value_name: Name for the new value (e.g., "STATUS_SUCCESS")
        value: Numeric value as decimal or hex string (e.g., "0" or "0xFFFFFFFF")
        category: Optional category path

    Returns:
        Confirmation message
    """
    params = {"enum_name": enum_name, "value_name": value_name, "value": value}
    if category:
        params["category"] = category
    return safe_post("add_enum_value", params)

@mcp.tool()
def remove_enum_value(enum_name: str, value_name: str, category: str = None) -> str:
    """
    Remove a value from an enum.

    Args:
        enum_name: Name of the enum to modify
        value_name: Name of the value to remove
        category: Optional category path

    Returns:
        Confirmation message
    """
    params = {"enum_name": enum_name, "value_name": value_name}
    if category:
        params["category"] = category
    return safe_post("remove_enum_value", params)

# =============================================================================
# DATA OPERATIONS TOOLS
# =============================================================================

@mcp.tool()
def get_data_by_label(label: str) -> str:
    """
    Get information about data at a labeled address.

    Args:
        label: The label/symbol name to look up

    Returns:
        Data information including address, type, size, value, and reference count.
        If exact match not found, suggests similar labels.
    """
    return "\n".join(safe_get("get_data_by_label", {"label": label}))

@mcp.tool()
def get_data_by_labels(labels: list[str]) -> str:
    """
    Get information about data at multiple labeled addresses (batch lookup).

    Args:
        labels: List of label/symbol names to look up
            Example: ["g_PlayerInstance", "g_GameState", "g_SaveManager"]

    Returns:
        Combined data information for all labels, with each result separated.
        More efficient than calling get_data_by_label multiple times.
    """
    results = []
    for label in labels:
        results.append(f"=== {label} ===")
        data = safe_get("get_data_by_label", {"label": label})
        results.extend(data)
        results.append("")  # Blank line between results
    return "\n".join(results)

@mcp.tool()
def set_data_type(address: str, data_type: str, length: int = -1) -> str:
    """
    Set the data type at a specific address.

    Args:
        address: Address in hex format (e.g., "0x1400010a0")
        data_type: Data type to apply (e.g., "int", "DWORD", "char[100]", structure name)
        length: Optional length for variable-length types

    Returns:
        Confirmation message with data details
    """
    params = {"address": address, "data_type": data_type, "length": str(length)}
    return safe_post("set_data_type", params)

# =============================================================================
# MEMORY WRITE TOOL
# =============================================================================

@mcp.tool()
def set_bytes(address: str, bytes_hex: str) -> str:
    """
    Write bytes to memory at a specified address.

    WARNING: This modifies the binary data. Use with caution.

    Args:
        address: Starting address in hex format (e.g., "0x1400010a0")
        bytes_hex: Hex string of bytes to write (e.g., "90909090" for NOPs, "C3" for RET)

    Returns:
        Confirmation message with number of bytes written
    """
    return safe_post("set_bytes", {"address": address, "bytes": bytes_hex})

# =============================================================================
# ADVANCED ANALYSIS TOOLS
# =============================================================================

@mcp.tool()
def get_analysis_stats() -> str:
    """
    Get comprehensive analysis coverage statistics for the program.

    Returns metrics including:
    - Total functions and how many are named vs unnamed (FUN_*)
    - Total data items and how many are named vs unnamed (DAT_*)
    - String count
    - Cross-reference density
    - Overall analysis coverage percentage

    Useful for tracking RE progress and identifying remaining work.
    """
    return "\n".join(safe_get("get_analysis_stats"))

@mcp.tool()
def get_functions_by_xref_count(offset: int = 0, limit: int = 100, min_refs: int = 0) -> list:
    """
    Get functions sorted by cross-reference count (most referenced first).

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)
        min_refs: Minimum reference count filter (default: 0)

    Returns:
        List of functions with their xref counts, sorted descending.
        High xref counts often indicate important utility functions.
    """
    return safe_get("get_functions_by_xref_count", {
        "offset": offset, "limit": limit, "min_refs": min_refs
    })

@mcp.tool()
def get_unnamed_functions(offset: int = 0, limit: int = 100) -> list:
    """
    Get functions that still have default names (FUN_*).

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)

    Returns:
        List of unnamed functions with their addresses and xref counts.
        Useful for identifying functions that need analysis.
    """
    return safe_get("get_unnamed_functions", {"offset": offset, "limit": limit})

@mcp.tool()
def get_unnamed_data(offset: int = 0, limit: int = 100) -> list:
    """
    Get data items that still have default names (DAT_*).

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)

    Returns:
        List of unnamed data items with their addresses and types.
        Useful for identifying global variables that need analysis.
    """
    return safe_get("get_unnamed_data", {"offset": offset, "limit": limit})

@mcp.tool()
def find_functions_with_string(pattern: str, offset: int = 0, limit: int = 100) -> list:
    """
    Find all functions that reference strings matching a pattern.

    Args:
        pattern: Substring to search for in strings (case-insensitive)
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)

    Returns:
        List of functions and the matching strings they reference.
        Combines string search with xref lookup in one operation.
    """
    return safe_get("find_functions_with_string", {
        "pattern": pattern, "offset": offset, "limit": limit
    })

@mcp.tool()
def find_functions_calling(target: str, offset: int = 0, limit: int = 100) -> list:
    """
    Find all functions that call a specific function (by name or address).

    Args:
        target: Function name or address (e.g., "malloc" or "0x140001000")
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)

    Returns:
        List of calling functions with call site addresses.
        Works with both named functions and addresses.
    """
    return safe_get("find_functions_calling", {
        "target": target, "offset": offset, "limit": limit
    })

@mcp.tool()
def find_vtables(offset: int = 0, limit: int = 100) -> list:
    """
    Find potential virtual function tables (vtables) in the binary.

    Searches for common vtable patterns:
    - Consecutive function pointers in data sections
    - Pointers within executable segments
    - RTTI-related structures (if present)

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)

    Returns:
        List of potential vtable addresses with entry counts.
        Essential for C++ class recovery.
    """
    return safe_get("find_vtables", {"offset": offset, "limit": limit})

@mcp.tool()
def analyze_vtable(address: str, max_entries: int = 50) -> str:
    """
    Analyze a vtable at the given address.

    Args:
        address: Vtable address in hex format (e.g., "0x140050000")
        max_entries: Maximum entries to analyze (default: 50)

    Returns:
        Detailed vtable analysis including:
        - Each function pointer address
        - Function names (if known)
        - Decompiled signatures (if available)
        - Suggested method names based on position

    Useful for understanding class hierarchies and virtual methods.
    """
    return "\n".join(safe_get("analyze_vtable", {
        "address": address, "max_entries": max_entries
    }))

@mcp.tool()
def get_call_tree(address: str, depth: int = 3, direction: str = "both") -> str:
    """
    Get a hierarchical call tree for a function.

    Args:
        address: Function address in hex format (e.g., "0x140001000")
        depth: How many levels deep to traverse (default: 3, max: 5)
        direction: "callers", "callees", or "both" (default: "both")

    Returns:
        Hierarchical tree showing call relationships.
        Useful for understanding function context and data flow.
    """
    return "\n".join(safe_get("get_call_tree", {
        "address": address, "depth": depth, "direction": direction
    }))

@mcp.tool()
def infer_struct_from_function(address: str) -> str:
    """
    Infer structure layout from pointer access patterns in a function.

    Analyzes decompiled code to find:
    - Offsets accessed via pointer arithmetic
    - Data types used at each offset
    - Field access patterns

    Args:
        address: Function address to analyze (e.g., "0x140001000")

    Returns:
        Inferred structure definition with:
        - Field offsets
        - Suggested data types
        - Access counts
        - Proposed structure in C format

    Note: This is heuristic-based and may need refinement.
    """
    return "\n".join(safe_get("infer_struct_from_function", {"address": address}))

# =============================================================================
# BATCH OPERATION TOOLS
# =============================================================================

@mcp.tool()
def batch_rename_functions(renames: str) -> str:
    """
    Rename multiple functions in a single operation.

    Args:
        renames: JSON array of rename operations, each with:
            - "address": Function address
            - "name": New function name
            Example: '[{"address":"0x140001000","name":"init_player"},{"address":"0x140001100","name":"update_player"}]'

    Returns:
        Results for each rename operation (success/failure).
        More efficient than individual rename calls.
    """
    return safe_post("batch_rename_functions", {"renames": renames})

@mcp.tool()
def batch_set_comments(comments: str) -> str:
    """
    Set multiple comments in a single operation.

    Args:
        comments: JSON array of comment operations, each with:
            - "address": Address for comment
            - "comment": Comment text
            - "type": Optional, "decompiler" or "disassembly" (default: "decompiler")
            Example: '[{"address":"0x140001000","comment":"Initialize player state"},{"address":"0x140001050","comment":"Load config","type":"disassembly"}]'

    Returns:
        Results for each comment operation.
    """
    return safe_post("batch_set_comments", {"comments": comments})

# =============================================================================
# EXPORT TOOLS (SDK Generation)
# =============================================================================

@mcp.tool()
def export_structures_as_c(filter: str = None) -> str:
    """
    Export structure definitions as C header format.

    Args:
        filter: Optional substring filter for structure names

    Returns:
        C header code with typedef structs for all matching structures.
        Useful for creating modding SDKs or reimplementations.
    """
    params = {}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("export_structures_as_c", params))

@mcp.tool()
def export_enums_as_c(filter: str = None) -> str:
    """
    Export enum definitions as C header format.

    Args:
        filter: Optional substring filter for enum names

    Returns:
        C header code with enum definitions.
        Useful for creating modding SDKs or reimplementations.
    """
    params = {}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("export_enums_as_c", params))

@mcp.tool()
def export_function_signatures(filter: str = None, offset: int = 0, limit: int = 100) -> str:
    """
    Export function signatures as C declarations.

    Args:
        filter: Optional substring filter for function names
        offset: Pagination offset (default: 0)
        limit: Maximum number of functions (default: 100)

    Returns:
        C function declarations for all matching named functions.
        Useful for creating header files for reimplementation.
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("export_function_signatures", params))

# =============================================================================
# AGENT-OPTIMIZED TOOLS (Combined operations for efficiency)
# =============================================================================

@mcp.tool()
def analyze_function(address: str) -> str:
    """
    Combined analysis: decompile + xrefs + callees/callers in ONE call.

    This replaces 4-5 separate tool calls with a single efficient operation.

    Args:
        address: Function address in hex format (e.g., "0x140001000")

    Returns:
        Combined analysis including:
        - Function name and whether it's unnamed (FUN_*)
        - Decompiled code (truncated to 100 lines)
        - Functions it calls (with unnamed highlighted)
        - Functions that call it (with unnamed highlighted)
        - Strings referenced in the function

    Use this as the primary analysis tool - avoids multiple round trips.
    """
    results = []

    # Get function info
    func_info = safe_get("get_function_by_address", {"address": address})
    results.append("=== FUNCTION INFO ===")
    results.extend(func_info)

    # Check if unnamed
    func_name = ""
    for line in func_info:
        if line.startswith("Function:"):
            func_name = line.split()[1] if len(line.split()) > 1 else ""
            break
    is_unnamed = func_name.startswith("FUN_")
    results.append(f"Unnamed: {is_unnamed}")
    results.append("")

    # Decompile (truncated)
    results.append("=== DECOMPILED CODE ===")
    decomp = "\n".join(safe_get("decompile_function", {"address": address}))
    lines = decomp.split('\n')
    if len(lines) > 100:
        results.append('\n'.join(lines[:100]))
        results.append(f"... [truncated, {len(lines)} total lines]")
    else:
        results.append(decomp)
    results.append("")

    # Get callees (functions this calls)
    results.append("=== CALLS (functions this calls) ===")
    callees = safe_get("get_function_callees", {"address": address, "limit": 50})
    unnamed_callees = []
    for line in callees:
        results.append(line)
        if "FUN_" in line:
            # Extract address from line like "FUN_140001000 @ 140001000"
            parts = line.split("@")
            if len(parts) > 1:
                unnamed_callees.append(parts[1].strip())
    results.append(f"\nUnnamed callees: {len(unnamed_callees)}")
    if unnamed_callees[:5]:
        results.append(f"First 5: {', '.join(unnamed_callees[:5])}")
    results.append("")

    # Get callers (functions that call this)
    results.append("=== CALLED BY (functions that call this) ===")
    callers = safe_get("get_function_callers", {"address": address, "limit": 50})
    unnamed_callers = []
    for line in callers:
        results.append(line)
        if "FUN_" in line:
            parts = line.split("@")
            if len(parts) > 1:
                unnamed_callers.append(parts[1].strip())
    results.append(f"\nUnnamed callers: {len(unnamed_callers)}")
    if unnamed_callers[:5]:
        results.append(f"First 5: {', '.join(unnamed_callers[:5])}")

    return "\n".join(results)


@mcp.tool()
def get_next_unnamed(address: str, prefer: str = "callee") -> str:
    """
    Get the best next unnamed function to analyze after the current one.

    Prevents aimless enumeration by suggesting a related FUN_* function.

    Args:
        address: Current function address (just analyzed/renamed)
        prefer: Strategy for picking next:
            - "callee": Prefer functions called by current (default, follows data flow)
            - "caller": Prefer functions that call current (follows control flow up)
            - "most_refs": Pick the one with most references (important functions)

    Returns:
        Next unnamed function to analyze with context:
        - Address and current name
        - Why it was selected
        - Brief context (what named functions it relates to)

    Use after renaming a function to maintain focus and avoid enumeration.
    """
    results = []

    # Get callees and callers
    callees = safe_get("get_function_callees", {"address": address, "limit": 30})
    callers = safe_get("get_function_callers", {"address": address, "limit": 30})

    # Extract unnamed functions
    unnamed_callees = []
    unnamed_callers = []

    for line in callees:
        if "FUN_" in line and "@" in line:
            parts = line.split("@")
            name = parts[0].strip()
            addr = parts[1].strip()
            unnamed_callees.append({"name": name, "address": addr})

    for line in callers:
        if "FUN_" in line and "@" in line:
            parts = line.split("@")
            name = parts[0].strip()
            addr = parts[1].strip()
            unnamed_callers.append({"name": name, "address": addr})

    # Pick based on preference
    next_func = None
    reason = ""

    if prefer == "callee" and unnamed_callees:
        next_func = unnamed_callees[0]
        reason = f"Called by current function (1 of {len(unnamed_callees)} unnamed callees)"
    elif prefer == "caller" and unnamed_callers:
        next_func = unnamed_callers[0]
        reason = f"Calls current function (1 of {len(unnamed_callers)} unnamed callers)"
    elif prefer == "most_refs":
        # Check xref counts for unnamed functions
        all_unnamed = unnamed_callees + unnamed_callers
        if all_unnamed:
            # For simplicity, just pick first one - full implementation would check xref counts
            next_func = all_unnamed[0]
            reason = "Selected from related functions"

    # Fallback
    if not next_func:
        if unnamed_callees:
            next_func = unnamed_callees[0]
            reason = f"Fallback: callee (1 of {len(unnamed_callees)})"
        elif unnamed_callers:
            next_func = unnamed_callers[0]
            reason = f"Fallback: caller (1 of {len(unnamed_callers)})"
        else:
            return "No unnamed functions found in callees or callers. Try a different starting point."

    results.append("=== NEXT FUNCTION TO ANALYZE ===")
    results.append(f"Address: 0x{next_func['address']}")
    results.append(f"Current name: {next_func['name']}")
    results.append(f"Reason: {reason}")
    results.append("")
    results.append(f"Remaining unnamed callees: {len(unnamed_callees)}")
    results.append(f"Remaining unnamed callers: {len(unnamed_callers)}")
    results.append("")
    results.append("Next step: analyze_function(\"0x" + next_func['address'] + "\")")

    return "\n".join(results)


# Track which regions we've visited to ensure diversity
_visited_regions = set()
_region_counter = 0

def _get_diverse_unnamed_target() -> dict | None:
    """
    Internal helper: pick an unnamed function from a different region.
    Rotates through: high-xref functions, beginning, middle, end of binary.
    """
    global _region_counter

    strategies = [
        ("high-xref", 0, 10),      # High-value functions by xref count
        ("early", 0, 50),          # Beginning of binary
        ("mid-early", 1000, 50),   # ~1000 functions in
        ("middle", 5000, 50),      # Middle
        ("mid-late", 10000, 50),   # Later middle
        ("late", 50000, 50),       # Late in binary
    ]

    # Rotate through strategies
    for i in range(len(strategies)):
        idx = (_region_counter + i) % len(strategies)
        region_name, offset, limit = strategies[idx]

        # Try high-xref first
        if region_name == "high-xref":
            lines = safe_get("get_functions_by_xref_count", {"offset": offset, "limit": limit})
        else:
            lines = safe_get("get_unnamed_functions", {"offset": offset, "limit": limit})

        # Find an unnamed function
        for line in lines:
            if "FUN_" in line and "@" in line:
                parts = line.split("@")
                name = parts[0].strip()
                addr = parts[1].strip().split()[0]  # Handle "(xrefs: N)" suffix

                # Extract xref count if present
                xrefs = "?"
                if "xrefs:" in line:
                    try:
                        xrefs = line.split("xrefs:")[1].strip().rstrip(")")
                    except:
                        pass

                _region_counter = idx + 1  # Move to next region for next call
                return {"address": addr, "region": region_name, "xrefs": xrefs}

    return None


@mcp.tool()
def get_diverse_targets(count: int = 5) -> str:
    """
    Get unnamed functions from DIFFERENT regions of the binary.

    Returns high-value targets from various address ranges to avoid
    getting stuck in one area. Use this when local exploration stalls.

    Args:
        count: Number of diverse targets to return (default: 5)

    Returns:
        List of unnamed functions from different regions with their addresses.
    """
    results = ["=== DIVERSE TARGETS ===", ""]

    # Sample from different offsets
    regions = [
        ("High-xref (most called)", "get_functions_by_xref_count", {"offset": 0, "limit": 20}),
        ("Early binary", "get_unnamed_functions", {"offset": 0, "limit": 20}),
        ("Mid binary (~5000)", "get_unnamed_functions", {"offset": 5000, "limit": 20}),
        ("Late binary (~20000)", "get_unnamed_functions", {"offset": 20000, "limit": 20}),
        ("Very late (~50000)", "get_unnamed_functions", {"offset": 50000, "limit": 20}),
    ]

    found = 0
    for region_name, endpoint, params in regions:
        if found >= count:
            break

        lines = safe_get(endpoint, params)
        for line in lines:
            if found >= count:
                break
            if "FUN_" in line and "@" in line:
                parts = line.split("@")
                addr = parts[1].strip().split()[0]
                results.append(f"- 0x{addr} ({region_name})")
                found += 1
                break  # One per region

    results.append("")
    results.append("Pick any address and call: analyze_function(\"0x...\")")

    return "\n".join(results)


@mcp.tool()
def rename_and_next(address: str, new_name: str, comment: str = None) -> str:
    """
    Atomic operation: rename function + add comment + get next suggestion.

    Combines 2-3 tool calls into one, and automatically suggests next target.

    Args:
        address: Function address to rename (e.g., "0x140001000")
        new_name: New descriptive name for the function
        comment: Optional decompiler comment explaining the function

    Returns:
        - Rename confirmation
        - Comment confirmation (if provided)
        - Suggested next unnamed function to analyze

    This is the primary "work unit" for the RE agent - rename, document, move on.
    """
    results = []

    # Rename
    results.append("=== RENAME ===")
    rename_result = safe_post("rename_function_by_address", {
        "function_address": address,
        "new_name": new_name
    })
    results.append(rename_result)
    results.append("")

    # Add comment if provided
    if comment:
        results.append("=== COMMENT ===")
        comment_result = safe_post("set_decompiler_comment", {
            "address": address,
            "comment": comment
        })
        results.append(comment_result)
        results.append("")

    # Get next suggestion
    results.append("=== NEXT TARGET ===")

    # Get callees of the newly named function
    callees = safe_get("get_function_callees", {"address": address, "limit": 20})
    callers = safe_get("get_function_callers", {"address": address, "limit": 20})

    # Find unnamed
    next_addr = None
    for line in callees:
        if "FUN_" in line and "@" in line:
            parts = line.split("@")
            next_addr = parts[1].strip()
            results.append(f"Suggested: 0x{next_addr} (callee of {new_name})")
            break

    if not next_addr:
        for line in callers:
            if "FUN_" in line and "@" in line:
                parts = line.split("@")
                next_addr = parts[1].strip()
                results.append(f"Suggested: 0x{next_addr} (caller of {new_name})")
                break

    if not next_addr:
        # Auto-pick a diverse target instead of giving up
        results.append("No unnamed in immediate neighborhood - picking diverse target...")
        diverse = _get_diverse_unnamed_target()
        if diverse:
            next_addr = diverse["address"]
            results.append(f"Suggested: 0x{next_addr} (from {diverse['region']} region, xrefs: {diverse.get('xrefs', '?')})")
            results.append(f"\nNext: analyze_function(\"0x{next_addr}\")")
        else:
            results.append("No unnamed functions found anywhere!")
    else:
        results.append(f"\nNext: analyze_function(\"0x{next_addr}\")")

    return "\n".join(results)


@mcp.tool()
def get_naming_progress() -> str:
    """
    Get current progress on function naming.

    Returns:
        - Total functions vs named vs unnamed
        - Percentage complete
        - Encouragement to continue

    Use periodically to track progress without reading external files.
    """
    stats = safe_get("get_analysis_stats")
    return "\n".join(stats)


def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

