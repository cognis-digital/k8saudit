#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(description="Forward k8saudit JSON findings to a webhook URL.")
    ap.add_argument("--url", required=True, help="Destination URL (http:// or https://)")
    ap.add_argument("--header", action="append", default=[], help="Extra header as 'Key: Value'")
    ap.add_argument("--timeout", type=int, default=15, metavar="SEC",
                    help="HTTP timeout in seconds (default: 15)")
    args = ap.parse_args()

    # Validate URL scheme before making any network call.
    if not args.url.startswith(("http://", "https://")):
        sys.stderr.write("error: --url must start with http:// or https://\n")
        return 2

    if args.timeout < 1:
        sys.stderr.write("error: --timeout must be a positive integer\n")
        return 2

    raw = sys.stdin.read()
    if not raw.strip():
        sys.stderr.write("error: no input received on stdin\n")
        return 2

    # Validate that stdin is valid JSON before sending.
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.stderr.write("error: stdin is not valid JSON: %s\n" % exc)
        return 2

    payload = raw.encode("utf-8")
    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        if ":" not in h:
            sys.stderr.write("error: --header %r is not in 'Key: Value' format\n" % h)
            return 2
        k, _, v = h.partition(":")
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as r:
            print("posted %d bytes -> %d" % (len(payload), r.status))
        return 0
    except Exception as e:
        sys.stderr.write("webhook error: %s\n" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
