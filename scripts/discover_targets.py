from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, overload

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "docs" / "targets.candidates.json"
REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0/servers"
DEFAULT_MAX_PAGES = 60
DEFAULT_LIMIT = 60
DEFAULT_PER_PUBLISHER = 2
REQUEST_TIMEOUT_SECONDS = 10
REQUEST_DELAY_SECONDS = 0.1


def fetch_page(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "mcp-audit-discovery/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError("Registry response must be a JSON object")
    return payload


def first_page_url(limit: int = 100) -> str:
    return f"{REGISTRY_URL}?limit={limit}"


def next_page_url(cursor: str, limit: int = 100) -> str:
    return f"{REGISTRY_URL}?limit={limit}&cursor={urllib.parse.quote(cursor, safe='')}"


def build_pinned_command(package: dict[str, Any]) -> str | None:
    registry_type = package.get("registryType")
    identifier = package.get("identifier")
    version = package.get("version")
    if not isinstance(registry_type, str) or not isinstance(identifier, str):
        return None
    if not isinstance(version, str) or not version:
        return None
    if registry_type == "npm":
        return f"npx -y {identifier}@{version}"
    if registry_type == "pypi":
        return f"uvx {identifier}=={version}"
    return None


def has_required_environment_variables(package: dict[str, Any]) -> bool:
    environment_variables = package.get("environmentVariables", [])
    if not isinstance(environment_variables, list):
        return True
    return any(
        isinstance(variable, dict) and variable.get("isRequired") is True
        for variable in environment_variables
    )


def has_required_positional_arguments(package: dict[str, Any]) -> bool:
    for field in ("packageArguments", "runtimeArguments"):
        arguments = package.get(field, [])
        if not isinstance(arguments, list):
            return True
        for argument in arguments:
            if (
                isinstance(argument, dict)
                and argument.get("type") == "positional"
                and argument.get("isRequired") is True
            ):
                return True
    return False


def is_stdio_package(package: dict[str, Any]) -> bool:
    transport = package.get("transport")
    return isinstance(transport, dict) and transport.get("type") == "stdio"


def source_url(server: dict[str, Any]) -> str:
    repository = server.get("repository")
    if isinstance(repository, dict):
        repository_url = repository.get("url")
        if isinstance(repository_url, str):
            return repository_url
    website_url = server.get("websiteUrl")
    if isinstance(website_url, str) and website_url:
        return website_url
    name = server.get("name")
    if isinstance(name, str):
        encoded_name = urllib.parse.quote(name, safe="")
        return f"https://registry.modelcontextprotocol.io/v0/servers/{encoded_name}"
    return "https://registry.modelcontextprotocol.io/"


def is_latest(entry: dict[str, Any]) -> bool:
    meta = entry.get("_meta")
    if not isinstance(meta, dict):
        return False
    official = meta.get("io.modelcontextprotocol.registry/official")
    if not isinstance(official, dict):
        return False
    return official.get("isLatest") is True


def candidate_from_entry(entry: dict[str, Any], fetched_at: str) -> dict[str, object] | None:
    server = entry.get("server")
    if not isinstance(server, dict):
        return None
    name = server.get("name")
    if not isinstance(name, str) or not name:
        return None
    packages = server.get("packages")
    if not isinstance(packages, list):
        return None

    for package in packages:
        if not isinstance(package, dict):
            continue
        if not is_stdio_package(package):
            continue
        if has_required_environment_variables(package):
            continue
        if has_required_positional_arguments(package):
            continue
        command = build_pinned_command(package)
        if command is None:
            continue
        package_version = package.get("version")
        if not isinstance(package_version, str) or not package_version:
            continue
        description_value = server.get("description")
        description = description_value if isinstance(description_value, str) else ""
        publisher = name.split("/", 1)[0]
        return {
            "name": name,
            "command": command,
            "source_url": source_url(server),
            "version": package_version,
            "fetched_at": fetched_at,
            "downloads": None,
            "description": description,
            "publisher": publisher,
            "_registry_type": package.get("registryType"),
            "_identifier": package.get("identifier"),
        }
    return None


def fetch_downloads(registry_type: str, identifier: str) -> int | None:
    encoded_identifier = urllib.parse.quote(identifier, safe="")
    if registry_type == "npm":
        url = f"https://api.npmjs.org/downloads/point/last-week/{encoded_identifier}"
    elif registry_type == "pypi":
        url = f"https://pypistats.org/api/packages/{encoded_identifier}/recent"
    else:
        return None

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "mcp-audit-discovery/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            payload = json.load(response)
    except Exception:
        return None
    return parse_download_count(registry_type, payload)


def parse_download_count(registry_type: str, payload: dict[str, Any]) -> int | None:
    if not isinstance(payload, dict):
        return None

    if registry_type == "npm":
        downloads = payload.get("downloads")
    else:
        data = payload.get("data")
        downloads = data.get("last_week") if isinstance(data, dict) else None
    return downloads if isinstance(downloads, int) and downloads >= 0 else None


def enrich_download_counts(
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    for index, candidate in enumerate(candidates):
        registry_type = candidate.get("_registry_type")
        identifier = candidate.get("_identifier")
        if not isinstance(registry_type, str) or not isinstance(identifier, str):
            candidate["downloads"] = None
        else:
            candidate["downloads"] = fetch_downloads(registry_type, identifier)
        if index + 1 < len(candidates):
            time.sleep(REQUEST_DELAY_SECONDS)
    return candidates


def rank_candidates(
    candidates: list[dict[str, object]],
    per_publisher: int,
    limit: int,
) -> list[dict[str, object]]:
    if per_publisher < 0:
        raise ValueError("per-publisher must be non-negative")
    if limit < 0:
        raise ValueError("limit must be non-negative")
    if per_publisher == 0 or limit == 0:
        return []

    def sort_key(candidate: dict[str, object]) -> tuple[bool, int]:
        downloads = candidate.get("downloads")
        if isinstance(downloads, int):
            return False, -downloads
        return True, 0

    ranked = sorted(candidates, key=sort_key)
    counts: dict[str, int] = {}
    selected: list[dict[str, object]] = []
    for candidate in ranked:
        publisher = candidate.get("publisher")
        if not isinstance(publisher, str):
            continue
        count = counts.get(publisher, 0)
        if count >= per_publisher:
            continue
        counts[publisher] = count + 1
        selected.append({
            key: value
            for key, value in candidate.items()
            if not key.startswith("_")
        })
        if len(selected) >= limit:
            break
    return selected


@overload
def paginate_and_discover(
    limit: int,
    fetcher: Any = fetch_page,
    fetched_at: str | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    include_stats: Literal[False] = False,
) -> list[dict[str, object]]: ...


@overload
def paginate_and_discover(
    limit: int,
    fetcher: Any = fetch_page,
    fetched_at: str | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    include_stats: Literal[True] = True,
) -> tuple[list[dict[str, object]], int, int]: ...


def paginate_and_discover(
    limit: int,
    fetcher: Any = fetch_page,
    fetched_at: str | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    include_stats: bool = False,
) -> list[dict[str, object]] | tuple[list[dict[str, object]], int, int]:
    if limit < 0:
        raise ValueError("limit must be non-negative")
    if max_pages < 0:
        raise ValueError("max-pages must be non-negative")
    if limit == 0:
        if include_stats:
            return [], 0, 0
        return []
    timestamp = fetched_at or datetime.now(UTC).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    candidates: dict[str, dict[str, object]] = {}
    cursor: str | None = None
    examined = 0
    passed = 0

    for page_index in range(max_pages):
        url = first_page_url() if cursor is None else next_page_url(cursor)
        payload = fetcher(url)
        servers = payload.get("servers")
        if not isinstance(servers, list):
            raise ValueError("Registry response is missing the servers array")

        examined += len(servers)
        for entry in servers:
            if not isinstance(entry, dict):
                continue
            candidate = candidate_from_entry(entry, timestamp)
            if candidate is None:
                continue
            passed += 1
            name_value = candidate["name"]
            if not isinstance(name_value, str):
                continue
            name = name_value
            existing = candidates.get(name)
            if existing is None:
                candidates[name] = candidate
            elif is_latest(entry) and not existing.get("_is_latest"):
                candidate["_is_latest"] = "true"
                candidates[name] = candidate

        if len(candidates) >= limit:
            break
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            break
        next_cursor = metadata.get("nextCursor")
        if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
            break
        cursor = next_cursor
        if page_index + 1 < max_pages:
            time.sleep(REQUEST_DELAY_SECONDS)

    result = sorted(
        (
            {key: value for key, value in candidate.items() if key != "_is_latest"}
            for candidate in candidates.values()
        ),
        key=lambda candidate: str(candidate["name"]),
    )[:limit]
    if include_stats:
        return result, examined, passed
    return result


def write_candidates(candidates: list[dict[str, object]], path: Path = OUTPUT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(candidates, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Discover pinned MCP registry targets")
    parser.add_argument("--rank", choices=["downloads"], default="downloads")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--per-publisher", type=int, default=DEFAULT_PER_PUBLISHER)
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)
    args = parser.parse_args(argv)
    if args.limit < 0:
        print("Error: --limit must be non-negative", file=sys.stderr)
        return 2
    if args.per_publisher < 0:
        print("Error: --per-publisher must be non-negative", file=sys.stderr)
        return 2
    if args.max_pages < 0:
        print("Error: --max-pages must be non-negative", file=sys.stderr)
        return 2
    try:
        discovery_result = paginate_and_discover(
            max(args.limit, 1000),
            max_pages=args.max_pages,
            include_stats=True,
        )
        if not isinstance(discovery_result, tuple):
            raise RuntimeError("Discovery stats were not returned")
        discovered, examined, passed = discovery_result
        discovered = enrich_download_counts(discovered)
        ranked = rank_candidates(discovered, args.per_publisher, args.limit)
        write_candidates(ranked)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(
        f"Examined {examined} registry entries; "
        f"{passed} passed filters. "
        f"Wrote {len(ranked)} candidates to {OUTPUT_PATH.relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
