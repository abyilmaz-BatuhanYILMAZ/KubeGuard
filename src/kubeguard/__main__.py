"""CLI entry: python -m kubeguard scan path.yaml [--format json|sarif]."""
from __future__ import annotations

import argparse
import sys

from .reporting import dump
from .scanner import ManifestError, RULES, SEVERITY_ORDER, scan_files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kubeguard", description="Read-only Kubernetes YAML security checks")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Inspect YAML files or directories without accessing a Kubernetes cluster")
    scan.add_argument("paths", nargs="+", help="Manifest paths (recursive for directories)")
    scan.add_argument("--format", choices=("human", "json", "sarif"), default="human")
    scan.add_argument("--fail-on", choices=("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"),
                      default="HIGH", help="Exit 1 for findings at or above this severity (default: HIGH)")
    sub.add_parser("list-rules", help="Show built-in static checks")
    args = parser.parse_args(argv)
    if args.command == "list-rules":
        for rule_id, (severity, message, fix) in sorted(RULES.items()):
            print(f"{rule_id} [{severity}] {message} — {fix}")
        return 0
    try:
        result = scan_files(args.paths)
    except (ManifestError, OSError, RecursionError) as exc:
        print(f"KubeGuard input error: {exc}", file=sys.stderr)
        return 2
    print(dump(result, args.format))
    if args.fail_on == "NONE":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in result.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
