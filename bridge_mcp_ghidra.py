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

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
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
def list_strings(offset: int = 0, limit: int = 100, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 100)
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

