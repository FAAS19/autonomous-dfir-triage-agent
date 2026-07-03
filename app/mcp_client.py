"""Shared MCP session helper for DFIR Triage Agent nodes.

ADK Workflow runs async-generator nodes inside its own TaskGroup. Raw
`mcp.client.stdio.stdio_client` uses AnyIO internally and requires that
its CancelScope start and end in the **same** task — which is violated
when the context manager spans across ADK's task-group boundary, causing
the "unhandled errors in a TaskGroup (1 sub-exception)" crash.

Fix: use ADK's own `SessionContext`, which pins the entire MCP lifecycle
(subprocess spawn → session init → close) to a single dedicated
background task that satisfies AnyIO's constraint.
"""

from __future__ import annotations

import sys
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from google.adk.tools.mcp_tool.session_context import SessionContext

# Absolute path to the FastMCP server entry point
_SERVER_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "mcp_server", "server.py")
)

_SERVER_PARAMS = StdioServerParameters(
    command=sys.executable,
    args=[_SERVER_PATH],
)


@asynccontextmanager
async def mcp_session() -> AsyncIterator[ClientSession]:
    """Async context manager yielding an initialized MCP ClientSession.

    Uses ADK's SessionContext to manage the stdio lifecycle in a dedicated
    background task, preventing AnyIO CancelScope violations inside ADK
    Workflow generators.

    Usage::

        async with mcp_session() as session:
            result = await session.call_tool("read_evidence_manifest", ...)
    """
    client = stdio_client(server=_SERVER_PARAMS)
    ctx = SessionContext(
        client=client,
        timeout=300.0,       # 5 min — anomaly detection can be slow
        sse_read_timeout=None,
        is_stdio=True,
    )
    async with ctx as session:
        yield session
