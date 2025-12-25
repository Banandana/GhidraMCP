"""
Bookmark and equate tools for GhidraMCP.

Provides tools for managing bookmarks (annotations) and equates (named constants).
"""

from .core import mcp, safe_get, safe_post


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
