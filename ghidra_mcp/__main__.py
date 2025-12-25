#!/usr/bin/env python3
"""
Entry point for running GhidraMCP as a module.

Usage:
    python -m ghidra_mcp [--ghidra-server URL]

Example:
    python -m ghidra_mcp --ghidra-server http://127.0.0.1:8080/
"""

import argparse
import sys

from . import mcp, set_server_url
from .core import DEFAULT_GHIDRA_SERVER


def main():
    """Main entry point for the GhidraMCP server."""
    parser = argparse.ArgumentParser(
        description="GhidraMCP - MCP bridge for Ghidra reverse engineering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python -m ghidra_mcp
    python -m ghidra_mcp --ghidra-server http://localhost:8080/

The Ghidra server must be running with the GhidraMCP plugin loaded.
"""
    )
    parser.add_argument(
        "--ghidra-server",
        default=DEFAULT_GHIDRA_SERVER,
        help=f"URL of the Ghidra HTTP server (default: {DEFAULT_GHIDRA_SERVER})"
    )

    args = parser.parse_args()

    # Configure the server URL
    set_server_url(args.ghidra_server)

    # Run the MCP server
    mcp.run()


if __name__ == "__main__":
    main()
