"""The reusable connector must not depend on an MCP runtime or local storage."""

import os
import subprocess
import sys
import textwrap
import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[1]


def run_isolated(code, tmp_path):
    env = {key: value for key, value in os.environ.items() if not key.startswith("SEC_AUDITOR_")}
    env.update(PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_core_embeds_without_mcp_auth_stack_sqlite_files_or_worker_tasks(tmp_path):
    result = run_isolated(
        """
        import asyncio
        import importlib.abc
        import sys
        from pathlib import Path

        forbidden = {"mcp", "starlette", "uvicorn", "jwt", "sqlite3"}
        class NoOptionalRuntime(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname.split(".")[0] in forbidden:
                    raise AssertionError(f"Core imported optional runtime: {fullname}")

        sys.meta_path.insert(0, NoOptionalRuntime())
        from sec_auditor.config import Settings
        from sec_auditor.connector import CloudConnector

        async def exercise():
            before = asyncio.all_tasks()
            settings = Settings(
                allowed_projects=["example-project"],
                allowed_alicloud_accounts=["1234567890123456"],
                allowed_alicloud_regions=["cn-hangzhou"],
            )
            async with CloudConnector(settings) as connector:
                assert connector.ready
                assert asyncio.all_tasks() == before
                catalog = connector.capabilities()
                assert catalog["providers"] == ["gcp", "alicloud"]
                assert catalog["gcp_resources"] and catalog["alicloud_resources"]
                assert not hasattr(connector, "store")
                assert not hasattr(connector, "start_assessment")
                assert not hasattr(connector, "run_checks")
            assert not connector.ready
            assert asyncio.all_tasks() == before
            assert not list(Path.cwd().iterdir())
            assert not forbidden.intersection(sys.modules)

        asyncio.run(exercise())
        """,
        tmp_path,
    )
    assert result.returncode == 0, result.stderr


def test_serve_without_optional_transport_gives_actionable_install_command(tmp_path):
    result = run_isolated(
        """
        import importlib.util
        import sys
        original_find = importlib.util.find_spec
        importlib.util.find_spec = lambda name, *args, **kwargs: (
            None if name == "mcp" else original_find(name, *args, **kwargs)
        )
        from sec_auditor.__main__ import main
        sys.argv = ["sec-auditor", "serve"]
        main()
        """,
        tmp_path,
    )
    assert result.returncode == 2
    assert "pip install 'sec-auditor[mcp]'" in result.stderr
    assert not result.stdout
    assert not list(tmp_path.iterdir())


def test_package_declares_mcp_as_optional_and_does_not_ship_auditor_modules():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    dependencies = project["dependencies"]
    optional = project["optional-dependencies"]["mcp"]
    for prefix in ("mcp", "PyJWT", "uvicorn"):
        assert not any(item.startswith(prefix) for item in dependencies)
        assert any(item.startswith(prefix) for item in optional)
    for filename in ("service.py", "state.py", "checks.py", "checks_alicloud.py"):
        assert not (ROOT / "src" / "sec_auditor" / filename).exists()
