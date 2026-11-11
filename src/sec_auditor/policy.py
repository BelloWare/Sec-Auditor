"""Verify project ancestry before spending the organization's read credentials."""

import asyncio
import re
import time
from typing import Any

from sec_auditor.config import Settings
from sec_auditor.transport import CloudAPIError, GoogleRestClient

PROJECT_RE = re.compile(r"(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})\Z")
SCOPE_RE = re.compile(r"(organizations|folders|projects)/([a-zA-Z0-9-]+)\Z")


class ScopeDenied(ValueError):
    pass


def validate_project(project: str) -> str:
    if not PROJECT_RE.fullmatch(project):
        raise ValueError("Invalid project ID or project number")
    return project


class ScopePolicy:
    def __init__(self, settings: Settings, client: GoogleRestClient):
        self.settings = settings
        self.client = client
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def _allowed_parent(self, parent: str) -> bool:
        visited: set[str] = set()
        for _ in range(32):
            if parent in visited:
                raise ScopeDenied("Resource hierarchy contains a cycle")
            visited.add(parent)
            match = SCOPE_RE.fullmatch(parent)
            if not match:
                return False
            kind, identifier = match.groups()
            if kind == "organizations":
                return identifier in self.settings.allowed_organizations
            if kind != "folders" or not identifier.isdigit():
                return False
            folder = await self.client.get(
                f"https://cloudresourcemanager.googleapis.com/v3/{parent}"
            )
            if folder.get("state") != "ACTIVE" or folder.get("name") != parent:
                return False
            parent = str(folder.get("parent", ""))
        raise ScopeDenied("Resource hierarchy exceeded the supported depth")

    async def authorize_project(self, project: str) -> dict[str, Any]:
        validate_project(project)
        if not self.settings.allowed_organizations and not self.settings.allowed_projects:
            raise ScopeDenied("GCP collection is not enabled in this deployment")
        async with self._lock:
            cached = self._cache.get(project)
            if cached and cached[0] > time.monotonic():
                return dict(cached[1])
            data = await self.client.get(
                f"https://cloudresourcemanager.googleapis.com/v3/projects/{project}"
            )
            canonical = str(data.get("projectId", ""))
            returned_name = str(data.get("name", ""))
            number = returned_name.removeprefix("projects/")
            if (
                not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", canonical)
                or not re.fullmatch(r"projects/[0-9]{1,30}", returned_name)
                or project not in {canonical, number}
            ):
                raise CloudAPIError(
                    "INVALID_RESPONSE", "Project lookup returned invalid identity metadata"
                )
            if data.get("state") != "ACTIVE":
                raise ScopeDenied("Project is not active")
            explicitly_allowed = bool(
                {project, canonical, number}.intersection(self.settings.allowed_projects)
            )
            if not explicitly_allowed and not await self._allowed_parent(
                str(data.get("parent", ""))
            ):
                raise ScopeDenied("Project is outside the configured audit scope")
            expires = time.monotonic() + self.settings.scope_cache_seconds
            for alias in (project, canonical, number):
                self._cache[alias] = (expires, dict(data))
            if len(self._cache) > 30_000:
                self._cache = {
                    key: val for key, val in self._cache.items() if val[0] > time.monotonic()
                }
            return dict(data)

    async def authorize_scope(self, scope: str) -> str:
        if not self.settings.allowed_organizations and not self.settings.allowed_projects:
            raise ScopeDenied("GCP collection is not enabled in this deployment")
        match = SCOPE_RE.fullmatch(scope)
        if not match:
            raise ScopeDenied("Scope must identify an organization, folder, or project")
        kind, identifier = match.groups()
        if kind == "projects":
            data = await self.authorize_project(identifier)
            return str(data["name"])
        if kind == "organizations" and identifier in self.settings.allowed_organizations:
            return scope
        if kind == "folders" and identifier.isdigit():
            folder = await self.client.get(
                f"https://cloudresourcemanager.googleapis.com/v3/{scope}"
            )
            if (
                folder.get("state") == "ACTIVE"
                and folder.get("name") == scope
                and await self._allowed_parent(str(folder.get("parent", "")))
            ):
                return scope
        raise ScopeDenied("Scope is outside the configured audit boundary")
