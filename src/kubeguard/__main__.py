"""CLI entry: python -m kubeguard scan path.yaml [--format json|sarif]."""
from __future__ import annotations

import argparse
import sys

from .cluster import scan_cluster
from .reporting import dump
from .scanner import ManifestError, RULES, SEVERITY_ORDER, scan_files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kubeguard", description="Read-only Kubernetes manifest and live-cluster security checks")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Analyze YAML files or read the live Kubernetes API")
    scan.add_argument("paths", nargs="*", help="YAML files or directories (omit in --cluster mode)")
    scan.add_argument("--cluster", action="store_true", help="Read live cluster objects using kubectl; never modify resources")
    scan.add_argument("--context", help="Required explicit kubeconfig context for --cluster")
    scan.add_argument("--kubeconfig", help="Optional kubeconfig file location for --cluster")
    scan.add_argument("--request-timeout", type=int, default=20,
                      help="Per-API-request timeout in seconds for --cluster (5–120)")
    scan.add_argument("--format", choices=("human", "json", "sarif"), default="human")
    scan.add_argument("--fail-on", choices=("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"),
                      default="HIGH", help="Exit 1 for findings at or above this severity (default: HIGH)")
    sub.add_parser("list-rules", help="Show built-in static checks")
    args = parser.parse_args(argv)
    if args.command == "list-rules":
        for rule_id, (severity, message, fix) in sorted(RULES.items()):
            print(f"{rule_id} [{severity}] {message} — {fix}")
        return 0
    if args.cluster:
        if args.paths or not args.context:
            parser.error("--cluster requires --context and does not accept YAML paths")
    elif not args.paths or args.context or args.kubeconfig:
        parser.error("choose YAML paths or --cluster --context NAME")
    try:
        result = (scan_cluster(context=args.context, kubeconfig=args.kubeconfig,
                               request_timeout=args.request_timeout)
                  if args.cluster else scan_files(args.paths))
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
