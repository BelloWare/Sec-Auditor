"""Exercise the actual packaged CLI and bidirectional stdio transport."""

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_packaged_stdio_handshake_and_tool_call(tmp_path):
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "sec_auditor", "serve", "--transport", "stdio"],
        env={
            "SEC_AUDITOR_ALLOWED_PROJECTS": '["example-project"]',
            "SEC_AUDITOR_STATE_PATH": str(tmp_path / "stdio.sqlite3"),
            "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
        },
    )
    async with (
        asyncio.timeout(20),
        stdio_client(parameters) as (reader, writer),
        ClientSession(reader, writer) as session,
    ):
        await session.initialize()
        tools = await session.list_tools()
        assert len(tools.tools) == 13
        result = await session.call_tool("capabilities", {})
        assert not result.is_error
        assert result.structured_content["providers"] == ["gcp"]
