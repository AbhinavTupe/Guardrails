"""HTML report rendering."""

from importlib.resources import files

from mcp_audit.models import ScanResult

DATA_PLACEHOLDER = "<!-- SCAN_DATA -->"


def render_html(result: ScanResult) -> str:
    """Render a scan result into the packaged single-file report template."""
    template = files("mcp_audit.report").joinpath("template.html").read_text(
        encoding="utf-8"
    )
    if template.count(DATA_PLACEHOLDER) != 1:
        raise RuntimeError("HTML report template must contain exactly one scan-data placeholder")

    scan_json = (
        result.to_json()
        .replace("<", "\\u003c")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    embedded_data = (
        '<script id="scan-data" type="application/json">'
        f"{scan_json}</script>"
    )
    return template.replace(DATA_PLACEHOLDER, embedded_data)
