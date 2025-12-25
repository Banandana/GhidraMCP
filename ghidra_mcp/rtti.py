"""
RTTI (Run-Time Type Information) analysis tools for GhidraMCP.

Provides tools for extracting class names, inheritance hierarchies,
and vtable information from MSVC RTTI structures.
"""

from .core import mcp, safe_get, safe_post


@mcp.tool()
def scan_for_rtti() -> str:
    """
    Scan the binary for RTTI (Run-Time Type Information) presence.

    MSVC C++ binaries with RTTI enabled contain:
    - Type descriptors with original class names
    - Class hierarchy descriptors
    - Complete object locators

    Returns:
        Summary of RTTI presence and sample class names found.
        If RTTI is present, this is EXTREMELY valuable for recreation.
    """
    return "\n".join(safe_get("scan_for_rtti"))


@mcp.tool()
def extract_all_rtti_classes(offset: int = 0, limit: int = 100) -> str:
    """
    Extract all class/struct names from RTTI type descriptors.

    Args:
        offset: Starting offset for pagination
        limit: Maximum number of results

    Returns:
        List of all class names found in RTTI, with namespaces.
    """
    return "\n".join(safe_get("extract_all_rtti_classes", {"offset": offset, "limit": limit}))


@mcp.tool()
def get_rtti_hierarchy(class_name: str) -> str:
    """
    Get the inheritance hierarchy for a class from RTTI.

    MSVC RTTI includes complete inheritance information in
    the Class Hierarchy Descriptor (??_R3).

    Args:
        class_name: Name of the class to analyze (without namespace)

    Returns:
        Inheritance tree and base class information.
    """
    return "\n".join(safe_get("get_rtti_hierarchy", {"class_name": class_name}))


@mcp.tool()
def find_rtti_for_vtable(vtable_address: str) -> str:
    """
    Find RTTI information associated with a vtable.

    In MSVC, the Complete Object Locator is stored immediately
    before the vtable (at vtable - 8 on x64).

    Args:
        vtable_address: Address of the vtable

    Returns:
        Class name and hierarchy from RTTI if available.
    """
    return "\n".join(safe_get("find_rtti_for_vtable", {"vtable_address": vtable_address}))


@mcp.tool()
def batch_extract_rtti_from_vtables(count: int = 20) -> str:
    """
    Find vtables and extract their class names from RTTI.

    This is the fastest way to get real class names:
    1. Find all vtables
    2. Read the Complete Object Locator before each
    3. Extract the original class name from RTTI

    Args:
        count: Number of vtables to process

    Returns:
        List of vtables with their real class names.
    """
    return "\n".join(safe_get("batch_extract_rtti_from_vtables", {"count": count}))


@mcp.tool()
def apply_rtti_names_to_vtables(dry_run: bool = True) -> str:
    """
    Automatically rename vtables and related functions using RTTI class names.

    This is a powerful automation that:
    1. Scans all vtables
    2. Extracts class names from RTTI
    3. Renames vtables to ClassName_vtable
    4. Optionally renames virtual methods with class prefix

    Args:
        dry_run: If True, only show what would be renamed. Set to False to apply.

    Returns:
        List of renames performed or planned.
    """
    params = {"dry_run": "true" if dry_run else "false"}
    return "\n".join(safe_get("apply_rtti_names_to_vtables", params))
