"""CLI entry point. STDIO emits protocol traffic only on stdout."""

import argparse
import getpass
import hashlib
import json
import logging
import sys

from sec_auditor.checks import list_checks
from sec_auditor.config import Settings


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sec-auditor", description="Restricted cloud security MCP"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Run the MCP server")
    serve.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", default=None, type=int)
    commands.add_parser(
        "checks", help="Print the deterministic check catalogue without cloud credentials"
    )
    catalog = commands.add_parser(
        "catalog", help="Print the compiled query contract without cloud credentials"
    )
    catalog.add_argument("--provider", choices=["gcp", "alicloud", "all"], default="all")
    commands.add_parser(
        "ram-policy",
        help="Print an Alibaba RAM policy for compiled metadata reads; review scopes before granting",
    )
    commands.add_parser(
        "hash-token", help="Read a machine bearer token privately and print only its SHA-256 digest"
    )
    arguments = parser.parse_args()
    if arguments.command == "checks":
        print(json.dumps([check.model_dump() for check in list_checks()], indent=2))
        return
    if arguments.command == "catalog":
        from sec_auditor.providers.alicloud_catalog import capabilities
        from sec_auditor.providers.capabilities import grouped_capabilities
        from sec_auditor.providers.gcp import GCPProvider

        result = {}
        if arguments.provider in {"all", "gcp"}:
            result["gcp"] = grouped_capabilities("gcp", GCPProvider(None).capabilities())
        if arguments.provider in {"all", "alicloud"}:
            result["alicloud"] = grouped_capabilities("alicloud", capabilities())
        print(json.dumps(result, indent=2))
        return
    if arguments.command == "ram-policy":
        from sec_auditor.providers.alicloud_catalog import required_ram_actions

        print(
            json.dumps(
                {
                    "Version": "1",
                    "Statement": [
                        {"Effect": "Allow", "Action": required_ram_actions(), "Resource": "*"}
                    ],
                },
                indent=2,
            )
        )
        return
    if arguments.command == "hash-token":
        token = (
            getpass.getpass("Bearer token: ")
            if sys.stdin.isatty()
            else sys.stdin.readline().rstrip("\r\n")
        )
        if len(token) < 32:
            parser.error("Use a randomly generated token of at least 32 characters")
        print(hashlib.sha256(token.encode()).hexdigest())
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )
    try:
        overrides = {
            key: value
            for key, value in {"host": arguments.host, "port": arguments.port}.items()
            if value is not None
        }
        settings = Settings(**overrides)
        from sec_auditor.server import build_server, create_app

        if arguments.transport == "stdio":
            server, _, _ = build_server(settings)
            server.run(transport="stdio")
        else:
            import uvicorn

            app = create_app(settings)
            uvicorn.run(
                app, host=settings.host, port=settings.port, log_level="info", access_log=False
            )
    except (ValueError, OSError) as exc:
        # Configuration exceptions never print token values or complete environment settings.
        logging.getLogger("sec_auditor").error("Startup failed: %s", type(exc).__name__)
        print(
            "Invalid configuration or unavailable state directory. See docs/deployment.md and the configured scope/authentication settings.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
