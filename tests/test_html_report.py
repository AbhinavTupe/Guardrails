import json
import re
import shlex
import sys
from html.parser import HTMLParser
from pathlib import Path

from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.models import ScanResult, ToolInfo
from mcp_audit.report.html import render_html

runner = CliRunner()
ROOT = Path(__file__).parents[1]


class ScriptCounter(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            self.count += 1


def test_html_file_contains_scan_json(tmp_path: Path) -> None:
    report_path = tmp_path / "report.html"
    command = shlex.join([sys.executable, str(ROOT / "testbed" / "clean_calc.py")])

    result = runner.invoke(app, ["scan", "--html", str(report_path), command])

    assert result.exit_code == 0
    html = report_path.read_text(encoding="utf-8")
    assert 'id="scan-data" type="application/json"' in html
    assert '"server_command":' in html
    assert '"name": "add"' in html
    assert f"Report written to {report_path}" in result.output


def test_script_closing_text_is_escaped_in_embedded_json() -> None:
    scan = ScanResult(
        server_command="test-server",
        tools=[
            ToolInfo(
                name="tool",
                description='</script><script>alert(1)</script>',
                input_schema={},
            )
        ],
    )

    html = render_html(scan)
    data = re.search(
        r'<script id="scan-data" type="application/json">(.*?)</script>',
        html,
        flags=re.DOTALL,
    )

    assert data is not None
    assert "</script>" not in data.group(1).lower()
    assert "\\u003c/script>" in data.group(1)
    script_counter = ScriptCounter()
    script_counter.feed(html)
    assert script_counter.count == 2


def test_report_template_has_no_external_script_or_style_urls() -> None:
    template = (ROOT / "mcp_audit" / "report" / "template.html").read_text(
        encoding="utf-8"
    )

    assert not re.search(r"""(?:src|href)\s*=\s*["']https?://""", template, re.IGNORECASE)


def test_clean_scan_html_exits_zero(tmp_path: Path) -> None:
    report_path = tmp_path / "clean-report.html"
    command = shlex.join([sys.executable, str(ROOT / "testbed" / "clean_calc.py")])

    result = runner.invoke(app, ["scan", command, "--html", str(report_path)])

    assert result.exit_code == 0
    assert report_path.is_file()
    html = report_path.read_text(encoding="utf-8")
    data = re.search(
        r'<script id="scan-data" type="application/json">(.*?)</script>',
        html,
        flags=re.DOTALL,
    )
    assert data is not None
    assert json.loads(data.group(1))["findings"] == []


def test_probe_scan_writes_html_report(tmp_path: Path) -> None:
    report_path = tmp_path / "probe-report.html"
    command = shlex.join([sys.executable, str(ROOT / "testbed" / "vuln_shell.py")])

    result = runner.invoke(app, ["scan", "--probe", "--html", str(report_path), command])

    assert result.exit_code == 1
    html = report_path.read_text(encoding="utf-8")
    data = re.search(
        r'<script id="scan-data" type="application/json">(.*?)</script>',
        html,
        flags=re.DOTALL,
    )
    assert data is not None
    assert any(item["rule_id"] == "PRB-002" for item in json.loads(data.group(1))["findings"])
