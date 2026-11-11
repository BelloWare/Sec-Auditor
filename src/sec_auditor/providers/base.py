"""Common collection boundary implemented by GCP and Alibaba Cloud adapters."""

from typing import Any, Protocol

from sec_auditor.models import CollectionResult


class CloudProvider(Protocol):
    name: str

    def capabilities(self) -> list[dict[str, Any]]: ...

    async def query_resources(
        self,
        kind: str,
        scope_id: str,
        *,
        location: str | None = None,
        operation: str = "list",
        parent: str | None = None,
        resource_id: str | None = None,
        selectors: dict[str, str] | None = None,
        page_size: int = 100,
        page_token: str | None = None,
    ) -> CollectionResult: ...
