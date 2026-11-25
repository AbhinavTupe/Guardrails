import json
from pathlib import Path

from scripts.discover_targets import (
    build_pinned_command,
    candidate_from_entry,
    has_required_environment_variables,
    has_required_positional_arguments,
    paginate_and_discover,
)

FIXTURE = Path(__file__).parent / "fixtures" / "registry_response.json"


def make_entry(
    name: str,
    registry_type: str = "npm",
    identifier: str = "example-package",
    version: str = "1.2.3",
    transport: str = "stdio",
    environment_variables: list[dict[str, object]] | None = None,
    package_arguments: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    package: dict[str, object] = {
        "registryType": registry_type,
        "identifier": identifier,
        "version": version,
        "transport": {"type": transport},
    }
    if environment_variables is not None:
        package["environmentVariables"] = environment_variables
    if package_arguments is not None:
        packageArguments = package_arguments
        package["packageArguments"] = packageArguments
    return {
        "server": {
            "name": name,
            "repository": {"url": "https://github.com/example/project"},
            "packages": [package],
        }
    }


def test_saved_fixture_filtering() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    entries = payload["servers"]

    candidates = [
        candidate
        for entry in entries
        if (candidate := candidate_from_entry(entry, "2026-11-25T00:00:00Z")) is not None
    ]

    assert [candidate["name"] for candidate in candidates] == [
        "io.example/clean-npm",
        "io.example/clean-pypi",
    ]


def test_pinned_command_building() -> None:
    assert build_pinned_command({
        "registryType": "npm",
        "identifier": "@scope/package",
        "version": "2.0.1",
    }) == "npx -y @scope/package@2.0.1"
    assert build_pinned_command({
        "registryType": "pypi",
        "identifier": "weather-mcp",
        "version": "3.4.5",
    }) == "uvx weather-mcp==3.4.5"


def test_required_environment_filter() -> None:
    assert has_required_environment_variables({
        "environmentVariables": [{"name": "TOKEN", "isRequired": True, "isSecret": True}]
    })
    assert not has_required_environment_variables({
        "environmentVariables": [{"name": "OPTIONAL", "isRequired": False}]
    })


def test_required_positional_argument_filter() -> None:
    assert has_required_positional_arguments({
        "packageArguments": [{"type": "positional", "isRequired": True}]
    })
    assert not has_required_positional_arguments({
        "packageArguments": [{"type": "positional", "isRequired": False}]
    })


def test_pagination_fetches_next_cursor() -> None:
    calls: list[str] = []

    def fetcher(url: str) -> dict[str, object]:
        calls.append(url)
        if len(calls) == 1:
            return {
                "servers": [make_entry("io.example/one")],
                "metadata": {"nextCursor": "page:2"},
            }
        return {
            "servers": [make_entry("io.example/two")],
            "metadata": {},
        }

    candidates = paginate_and_discover(
        2,
        fetcher=fetcher,
        fetched_at="2026-11-25T00:00:00Z",
    )

    assert [candidate["name"] for candidate in candidates] == [
        "io.example/one",
        "io.example/two",
    ]
    assert len(calls) == 2
    assert "cursor=page%3A2" in calls[1]
