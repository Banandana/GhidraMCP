"""
Agent workflow tools for GhidraMCP.

Provides high-level tools optimized for automated reverse engineering workflows,
including combined analysis, batch naming, and parallel worker support.
"""

from .core import mcp, safe_get, safe_post


# =============================================================================
# Combined Analysis Tools
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
    return "\n".join(safe_get("analyze_function", {"address": address}))


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
    return "\n".join(safe_get("get_next_unnamed", {"address": address, "prefer": prefer}))


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
    return "\n".join(safe_get("get_diverse_targets", {"count": count}))


# =============================================================================
# Rename Workflow Tools
# =============================================================================

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
    params = {"address": address, "new_name": new_name}
    if comment:
        params["comment"] = comment
    return "\n".join(safe_get("rename_and_next", params))


@mcp.tool()
def rename_and_analyze_next(address: str, new_name: str, comment: str = None) -> str:
    """
    FASTEST workflow: Rename current function AND get full analysis of next target in ONE call.

    This is 3x faster than separate analyze→rename→analyze calls.

    Args:
        address: Current function address to rename
        new_name: New name for current function
        comment: Optional comment for current function

    Returns:
        - Rename confirmation
        - Next function's FULL analysis (decompile + callees + callers)
        - Ready to immediately call rename_and_analyze_next again
    """
    params = {"address": address, "new_name": new_name}
    if comment:
        params["comment"] = comment
    return "\n".join(safe_get("rename_and_analyze_next", params))


# =============================================================================
# Batch Analysis Tools
# =============================================================================

@mcp.tool()
def batch_analyze(count: int = 10) -> str:
    """
    Get multiple unnamed functions for batch naming. FASTEST method.

    Returns decompiled code for N functions at once. You then call
    batch_rename_and_continue with all names at once.

    Args:
        count: Number of functions to analyze (default: 10, max: 20)

    Returns:
        Multiple functions with their code, ready for batch naming.

    OPTIMIZED: Makes 1 list call + N decompile calls (was 5 + 2N calls).
    """
    count = min(count, 20)
    results = [f"=== BATCH OF {count} FUNCTIONS ===\n"]

    # Get unnamed functions in a single call with extra buffer
    lines = safe_get("get_unnamed_functions", {"offset": 0, "limit": count * 3})

    # Parse and filter to truly unnamed functions
    found = []
    for line in lines:
        if len(found) >= count:
            break
        if "FUN_" in line and "@" in line:
            addr = line.split("@")[1].strip().split()[0]
            if addr not in [f[0] for f in found]:
                found.append((addr, line))

    # Analyze each function - decompile only (skip callees to reduce calls)
    for i, (addr, info) in enumerate(found, 1):
        results.append(f"--- FUNCTION {i}/{len(found)}: 0x{addr} ---")

        # Get decompiled code (truncated)
        decomp = safe_get("decompile_function", {"address": addr})
        code_lines = [l for l in decomp if l.strip()][:30]
        results.extend(code_lines)
        if len(decomp) > 30:
            results.append(f"  ... [{len(decomp)} lines total]")
        results.append("")

    results.append("=" * 50)
    results.append("Now call: batch_rename_and_continue(\"name1, name2, ...\")")
    results.append(f"Addresses in order: {', '.join('0x' + f[0] for f in found)}")

    return "\n".join(results)


@mcp.tool()
def batch_rename_and_continue(names: str) -> str:
    """
    Rename multiple functions at once and get the next batch. FASTEST method.

    Args:
        names: Comma-separated names in order shown by batch_analyze
               Example: "InitPlayer, LoadConfig, ProcessInput, HandleEvent, SetupGame"

    Returns:
        Confirmation of renames + next batch of functions to name.
    """
    return "\n".join(safe_get("batch_rename_and_continue", {"names": names}))


# =============================================================================
# Parallel Worker Tools
# =============================================================================

@mcp.tool()
def get_unnamed_at_offset(worker_offset: int, limit: int = 10) -> str:
    """
    Get unnamed functions starting at a specific offset in the list.

    Use this for parallel workers - each worker uses a different offset.
    Worker 0: offset 0, Worker 1: offset 50000, Worker 2: offset 100000, etc.

    Args:
        worker_offset: Starting offset in the unnamed functions list
        limit: Maximum number of functions to return (default 10)

    Returns:
        List of unnamed functions with decompiled preview.
    """
    results = [f"=== UNNAMED FUNCTIONS @ OFFSET {worker_offset} ===\n"]

    all_unnamed = safe_get("get_unnamed_functions", {"offset": worker_offset, "limit": limit + 10})

    found = []
    for line in all_unnamed:
        if len(found) >= limit:
            break
        if "FUN_" in line and "@" in line:
            try:
                addr_str = line.split("@")[1].strip().split()[0]
                found.append(addr_str)
            except (IndexError, ValueError):
                continue

    if not found:
        results.append(f"No unnamed functions found at offset {worker_offset}.")
        results.append(f"Worker may have completed its range or offset is too high.")
        return "\n".join(results)

    results.append(f"Found {len(found)} unnamed functions:\n")

    # Decompile each
    for i, addr in enumerate(found, 1):
        results.append(f"--- {i}. 0x{addr} ---")
        decomp = safe_get("decompile_function", {"address": addr})
        code_lines = [l for l in decomp if l.strip()][:15]
        results.extend(code_lines)
        if len(decomp) > 15:
            results.append(f"  ... [{len(decomp)} lines]")

        callees = safe_get("get_function_callees", {"address": addr, "limit": 5})
        named = [l.split("@")[0].strip() for l in callees if "@" in l and "FUN_" not in l][:3]
        if named:
            results.append(f"  Calls: {', '.join(named)}")
        results.append("")

    return "\n".join(results)


@mcp.tool()
def get_unnamed_by_address_range(start_addr: str, end_addr: str, limit: int = 10) -> str:
    """
    Get unnamed functions within an address range.

    Args:
        start_addr: Start of range (e.g., "0x140000000")
        end_addr: End of range (e.g., "0x141000000")
        limit: Max functions to return (default 10)

    Returns:
        Unnamed functions in the specified range with decompiled preview.

    Use this for parallel workers - each worker takes a non-overlapping address range.
    Address ranges are stable (don't change as functions get renamed), unlike offsets.

    Example division for 4 workers on a binary from 0x140000000 to 0x144000000:
        Worker 0: start=0x140000000, end=0x141000000
        Worker 1: start=0x141000000, end=0x142000000
        Worker 2: start=0x142000000, end=0x143000000
        Worker 3: start=0x143000000, end=0x144000000
    """
    results = [f"=== UNNAMED FUNCTIONS IN RANGE {start_addr} - {end_addr} ===\n"]

    # Normalize addresses
    start = start_addr.lower().replace("0x", "")
    end = end_addr.lower().replace("0x", "")

    try:
        start_int = int(start, 16)
        end_int = int(end, 16)
    except ValueError:
        return f"Invalid address format: {start_addr} or {end_addr}"

    # Get a batch of unnamed functions (we'll filter by range)
    all_unnamed = safe_get("get_unnamed_functions", {"offset": 0, "limit": limit * 10})

    found = []
    for line in all_unnamed:
        if len(found) >= limit:
            break
        if "FUN_" in line and "@" in line:
            try:
                addr_str = line.split("@")[1].strip().split()[0]
                addr_int = int(addr_str, 16)
                if start_int <= addr_int < end_int:
                    found.append(addr_str)
            except (IndexError, ValueError):
                continue

    if not found:
        results.append(f"No unnamed functions found in range {start_addr} - {end_addr}.")
        results.append("Range may be fully analyzed or too narrow.")
        return "\n".join(results)

    results.append(f"Found {len(found)} unnamed functions in range:\n")

    # Decompile each (skip callees for efficiency)
    for i, addr in enumerate(found, 1):
        results.append(f"--- {i}. 0x{addr} ---")
        decomp = safe_get("decompile_function", {"address": addr})
        code_lines = [l for l in decomp if l.strip()][:20]
        results.extend(code_lines)
        if len(decomp) > 20:
            results.append(f"  ... [{len(decomp)} lines]")
        results.append("")

    return "\n".join(results)


@mcp.tool()
def batch_rename_at_offset(names: str, worker_offset: int) -> str:
    """
    Rename functions and get next batch from the worker's offset.

    Args:
        names: Comma-separated list of "addr:name" pairs, e.g., "140001000:Init_Player, 140001100:Update_State"
        worker_offset: Worker's current offset in the unnamed functions list

    Returns:
        Rename results and next batch of unnamed functions.
    """
    results = ["=== BATCH RENAME ===\n"]

    # Parse name pairs
    pairs = [p.strip() for p in names.split(",") if p.strip()]
    renamed_count = 0

    for pair in pairs:
        if ":" not in pair:
            results.append(f"✗ Invalid format: {pair} (expected addr:name)")
            continue

        parts = pair.split(":", 1)
        addr = parts[0].strip()
        name = parts[1].strip()

        # Normalize address
        if not addr.startswith("0x"):
            addr = "0x" + addr

        rename_result = safe_post("rename_function_by_address", {
            "address": addr,
            "newName": name
        })
        results.append(f"✓ {addr} → {name}: {rename_result}")
        renamed_count += 1

    results.append(f"\nRenamed {renamed_count}/{len(pairs)} functions\n")

    # Get next batch
    results.append("=== NEXT BATCH ===\n")
    next_batch = get_unnamed_at_offset(worker_offset + renamed_count, limit=10)
    results.append(next_batch)

    return "\n".join(results)
