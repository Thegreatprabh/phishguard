from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .github import scan_github_event
from .models import ScanResult
from .scanner import scan_file, scan_html, scan_text, scan_url


RISK_ORDER = {"safe": 0, "suspicious": 1, "dangerous": 2}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(_normalize_global_options(argv if argv is not None else sys.argv[1:]))
    result: ScanResult | list[ScanResult]

    if args.command == "scan-url":
        result = scan_url(args.url, fetch=args.fetch, timeout=args.timeout)
    elif args.command == "scan-html":
        html = Path(args.file).read_text(encoding="utf-8", errors="replace")
        result = scan_html(html, page_url=args.url)
    elif args.command == "scan-text":
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        result = scan_text(text, target=args.file)
    elif args.command == "scan-files":
        result = [scan_file(Path(path)) for path in args.files]
    elif args.command == "scan-github-event":
        result = scan_github_event(Path(args.file))
    else:
        parser.error("unknown command")

    emit(result, as_json=args.json)
    return exit_code(result, fail_on=args.fail_on)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishguard", description="Phishing detector for URLs, text, HTML, and GitHub workflows.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument(
        "--fail-on",
        choices=("safe", "suspicious", "dangerous", "never"),
        default="never",
        help="Exit with code 2 when this risk level or higher is found.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_url_parser = sub.add_parser("scan-url", help="Scan a single URL.")
    scan_url_parser.add_argument("url")
    scan_url_parser.add_argument("--fetch", action="store_true", help="Fetch and analyze HTML content.")
    scan_url_parser.add_argument("--timeout", type=float, default=8.0)

    html_parser = sub.add_parser("scan-html", help="Scan a local HTML file.")
    html_parser.add_argument("file")
    html_parser.add_argument("--url", help="Original page URL, if known.")

    text_parser = sub.add_parser("scan-text", help="Scan a local text file.")
    text_parser.add_argument("file")

    files_parser = sub.add_parser("scan-files", help="Scan many local files.")
    files_parser.add_argument("files", nargs="+")

    event_parser = sub.add_parser("scan-github-event", help="Scan a GitHub event JSON file.")
    event_parser.add_argument("file")

    return parser


def _normalize_global_options(argv: list[str]) -> list[str]:
    """Allow global flags before or after the subcommand."""
    global_args: list[str] = []
    remaining: list[str] = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--json":
            global_args.append(arg)
            index += 1
            continue
        if arg == "--fail-on" and index + 1 < len(argv):
            global_args.extend([arg, argv[index + 1]])
            index += 2
            continue
        remaining.append(arg)
        index += 1
    return global_args + remaining


def emit(result: ScanResult | list[ScanResult], as_json: bool) -> None:
    if as_json:
        if isinstance(result, list):
            print(json.dumps([item.to_dict() for item in result], indent=2, sort_keys=True))
        else:
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return

    results = result if isinstance(result, list) else [result]
    for item in results:
        print(f"{item.risk.upper():10} score={item.score:3} kind={item.kind} target={item.target}")
        if item.category != "clean":
            brand = f" brand={item.brand}" if item.brand else ""
            print(f"  category={item.category}{brand}")
        for evidence in item.evidence:
            print(f"  +{evidence.score:02d} {evidence.label}: {evidence.detail}")


def exit_code(result: ScanResult | list[ScanResult], fail_on: str) -> int:
    if fail_on == "never":
        return 0
    threshold = RISK_ORDER[fail_on]
    results = result if isinstance(result, list) else [result]
    if any(RISK_ORDER[item.risk] >= threshold for item in results):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
