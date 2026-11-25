from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "docs" / "targets.candidates.json"
REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0/servers"
MAX_PAGES = 10
DEFAULT_LIMIT = 60


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


def candidate_from_entry(entry: dict[str, Any], fetched_at: str) -> dict[str, str] | None:
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
        return {
            "name": name,
            "command": command,
            "source_url": source_url(server),
            "version": package_version,
            "fetched_at": fetched_at,
        }
    return None


def paginate_and_discover(
    limit: int,
    fetcher: Any = fetch_page,
    fetched_at: str | None = None,
) -> list[dict[str, str]]:
    if limit < 0:
        raise ValueError("limit must be non-negative")
    if limit == 0:
        return []
    timestamp = fetched_at or datetime.now(UTC).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    candidates: dict[str, dict[str, str]] = {}
    cursor: str | None = None

    for _ in range(MAX_PAGES):
        url = first_page_url() if cursor is None else next_page_url(cursor)
        payload = fetcher(url)
        servers = payload.get("servers")
        if not isinstance(servers, list):
            raise ValueError("Registry response is missing the servers array")

        for entry in servers:
            if not isinstance(entry, dict):
                continue
            candidate = candidate_from_entry(entry, timestamp)
            if candidate is None:
                continue
            name = candidate["name"]
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

    return sorted(
        (
            {key: value for key, value in candidate.items() if key != "_is_latest"}
            for candidate in candidates.values()
        ),
        key=lambda candidate: candidate["name"],
    )[:limit]


def write_candidates(candidates: list[dict[str, str]], path: Path = OUTPUT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(candidates, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Discover pinned MCP registry targets")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    args = parser.parse_args(argv)
    if args.limit < 0:
        print("Error: --limit must be non-negative", file=sys.stderr)
        return 2
    try:
        candidates = paginate_and_discover(args.limit)
        write_candidates(candidates)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {len(candidates)} candidates to {OUTPUT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
