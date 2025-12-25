"""
Memory operation tools for GhidraMCP.

Provides tools for reading memory, searching for byte patterns,
analyzing basic blocks, and modifying memory.
"""

from .core import mcp, safe_get, safe_post


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
