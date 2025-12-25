"""
Vtable analysis tools for GhidraMCP.

Provides tools for finding and analyzing virtual function tables,
which are essential for C++ reverse engineering.
"""

from ..core import mcp, safe_get, safe_post


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
        "address": address,
        "max_entries": max_entries
    }))


@mcp.tool()
def batch_analyze_vtables(count: int = 5) -> str:
    """
    Find and analyze multiple vtables, suggesting class names.

    Args:
        count: Number of vtables to analyze

    Returns:
        Vtable analysis with suggested method names and class structure.
    """
    results = ["=== BATCH VTABLE ANALYSIS ===\n"]

    # Find vtables
    vtables = safe_get("find_vtables", {"offset": 0, "limit": count * 2})

    analyzed = 0
    for line in vtables:
        if analyzed >= count:
            break
        if "@" not in line:
            continue

        addr = line.split("@")[-1].strip().split()[0]
        results.append(f"--- VTABLE at 0x{addr} ---")

        # Analyze this vtable
        vtable_info = safe_get("analyze_vtable", {"address": addr, "max_entries": 10})

        # Extract method info
        methods = []
        for vline in vtable_info:
            if "→" in vline or "->" in vline:
                methods.append(vline.strip())

        if methods:
            results.append(f"  {len(methods)} methods found")
            for m in methods[:5]:
                results.append(f"    {m}")
            if len(methods) > 5:
                results.append(f"    ... and {len(methods) - 5} more")

        results.append("")
        analyzed += 1

    results.append(f"\nAnalyzed {analyzed} vtables")
    results.append("\nUse analyze_vtable(\"0x...\", max_entries=50) for full details")

    return "\n".join(results)


@mcp.tool()
def create_class_from_vtable(vtable_address: str, class_name: str) -> str:
    """
    Create a struct representing a class based on vtable analysis.

    Args:
        vtable_address: Address of the vtable
        class_name: Name for the class

    Returns:
        Created struct with vtable pointer and analysis of virtual methods.
    """
    results = [f"=== CREATING CLASS: {class_name} ===\n"]

    # Analyze vtable
    vtable_info = safe_get("analyze_vtable", {"address": vtable_address, "max_entries": 30})

    # Create base struct
    create_result = safe_post("create_struct", {"name": class_name, "size": "8"})
    results.append(f"Struct created: {create_result}")

    # Add vtable pointer as first field
    add_result = safe_post("add_struct_member", {
        "struct_name": class_name,
        "field_name": "vtable",
        "data_type": "void*",
        "offset": "0"
    })
    results.append(f"Added vtable pointer: {add_result}")

    # Parse vtable methods and suggest renames
    results.append("\nVirtual methods found:")
    method_count = 0
    for line in vtable_info:
        if "→" in line or "->" in line or "0x" in line:
            results.append(f"  {line.strip()}")
            method_count += 1

    results.append(f"\nTotal: {method_count} virtual methods")
    results.append(f"\nSuggested next steps:")
    results.append(f"1. Rename vtable: rename_data(\"{vtable_address}\", \"{class_name}_vtable\")")
    results.append(f"2. Rename methods with class prefix: {class_name}_Method1, etc.")

    return "\n".join(results)
