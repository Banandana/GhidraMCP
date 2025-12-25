"""
Analysis statistics tools for GhidraMCP.

Provides tools for getting analysis coverage metrics, finding unnamed
functions/data, and tracking analysis progress.
"""

from ..core import mcp, safe_get


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
        "offset": offset,
        "limit": limit,
        "min_refs": min_refs
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
        "pattern": pattern,
        "offset": offset,
        "limit": limit
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
        "target": target,
        "offset": offset,
        "limit": limit
    })


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
    return "\n".join(safe_get("get_naming_progress"))
