"""
Cross-reference and call graph tools for GhidraMCP.

Provides tools for analyzing cross-references, function callers/callees,
and call trees.
"""

from .core import mcp, safe_get


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
        "address": address,
        "depth": depth,
        "direction": direction
    }))
