"""One MCP discovery shape across provider-native query catalogs."""

from copy import deepcopy
from typing import Any


def grouped_capabilities(provider: str, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for original in entries:
        entry = deepcopy(original)
        kind = entry["kind"]
        if "queries" in entry:
            entry["provider"] = provider
            grouped[kind] = entry
            continue
        operation = entry.get("operation", "list")
        item = grouped.setdefault(
            kind,
            {
                "provider": provider,
                "kind": kind,
                "description": entry.get("description", ""),
                "operations": [],
                "queries": {},
            },
        )
        item["operations"].append(operation)
        query = {
            key: value
            for key, value in entry.items()
            if key not in {"provider", "kind", "operations"}
        }
        query["scope_types"] = entry.get(
            "scope_types", ["accounts"] if provider == "alicloud" else ["projects"]
        )
        query["requires_parent"] = entry.get("requires_parent", entry.get("parent_required", False))
        query["requires_resource_id"] = entry.get(
            "requires_resource_id", entry.get("resource_id_required", False)
        )
        query["requires_location"] = entry.get(
            "requires_location", entry.get("location_required", False)
        )
        selectors = query.get("selectors", {})
        if isinstance(selectors, list):
            query["selectors"] = {
                name: {"required": name in query.get("required_selectors", [])}
                for name in selectors
            }
        item["queries"][operation] = query
    return [grouped[key] for key in sorted(grouped)]
