"""
Pattern inference tools for GhidraMCP.

Provides tools for inferring structure layouts from code patterns,
detecting enums from switch statements, and automated pattern analysis.
"""

from ..core import mcp, safe_get, safe_post


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


@mcp.tool()
def detect_enum_from_switch(address: str) -> str:
    """
    Analyze a function for switch statements and suggest enum values.

    Looks for patterns like:
    - switch(x) with case 0, 1, 2, 3...
    - if (x == 0) else if (x == 1)...
    - Comparisons against sequential/related constants

    Args:
        address: Function address to analyze

    Returns:
        Detected enum candidates with suggested names based on context.
        Ready to create with create_enum + add_enum_value.
    """
    return "\n".join(safe_get("detect_enum_from_switch", {"address": address}))


@mcp.tool()
def batch_detect_enums(count: int = 10) -> str:
    """
    Scan multiple functions for potential enums (switch statements).

    Prioritizes functions with:
    - "State", "Type", "Mode", "Kind" in name
    - High switch complexity

    Args:
        count: Number of functions to scan (default: 10)

    Returns:
        List of functions with detected enum patterns.
    """
    return "\n".join(safe_get("batch_detect_enums", {"count": count}))


@mcp.tool()
def detect_struct_from_access(address: str) -> str:
    """
    Analyze field access patterns to infer structure layout.

    Looks for patterns like:
    - param_1[offset]
    - *(type *)(ptr + offset)
    - ptr->field patterns in decompiled code

    Args:
        address: Function address to analyze

    Returns:
        Inferred structure with field offsets, types, and suggested names.
    """
    return "\n".join(safe_get("detect_struct_from_access", {"address": address}))


@mcp.tool()
def batch_detect_structs(count: int = 10) -> str:
    """
    Scan functions for struct access patterns.

    Prioritizes:
    - Constructor/destructor functions
    - Init* functions
    - Functions with many offset accesses

    Args:
        count: Number of functions to scan

    Returns:
        List of functions with detected struct patterns.
    """
    return "\n".join(safe_get("batch_detect_structs", {"count": count}))


@mcp.tool()
def post_naming_analysis(depth: str = "quick") -> str:
    """
    Run combined analysis after function naming is complete.

    This is the recommended entry point after finishing function naming.
    It scans for enums, structs, and vtables in one operation.

    Args:
        depth: "quick" (5 of each), "medium" (15 of each), "thorough" (50 of each)

    Returns:
        Summary of all detected patterns ready for batch creation.
    """
    return "\n".join(safe_get("post_naming_analysis", {"depth": depth}))
