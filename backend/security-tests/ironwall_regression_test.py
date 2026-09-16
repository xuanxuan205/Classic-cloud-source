#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IronWall: black-box payload regression matrix.

Contract:
  * Attack payloads MUST be answered by the engine (403/406/418/444/503/429),
    never by the upstream app with 200. A 200 on an attack payload = MISS -> exit non-zero.
  * Benign controls should stay 200; anything else is a WARNING (environmental,
    e.g. tester IP already banned by repeated tests), not a failure by default.
  * Default target: https://example.com  (override with env IRONWALL_BASE_URL)
  * Exit code: 0 = matrix passed, non-zero = at least one attack payload leaked through.

WARNING: this script fires real attack signatures at the target. The engine will
record and may ban the source IP (by design). Run it from a disposable / non-critical
source address, and never from the same IP you use to administer the site.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE = "https://example.com"
BLOCK_STATUS = {403, 406, 418, 444, 503, 429}
UA = "ironwall-regression/1.0"


def build_matrix():
    """(name, kind, method, path, params, body, headers) entries."""
    attack = "attack"
    benign = "benign"
    post_only = "post"
    entries = [
        ("sql_quote", attack, "GET", "/api/version/info", {"q": "1' OR '1'='1"}, None, None),
        ("sql_union", attack, "GET", "/api/version/info", {"q": "1 UNION SELECT password FROM users"}, None, None),
        ("sql_mysql_var", attack, "GET", "/api/version/info", {"q": "1 OR @@version"}, None, None),
        ("sql_concat", attack, "GET", "/api/version/info", {"q": "admin'||'1"}, None, None),
        ("xss_script", attack, "GET", "/api/version/info", {"q": "<script>alert(1)</script>"}, None, None),
        ("xss_img", attack, "GET", "/api/version/info", {"q": "\"><img src=x onerror=alert(1)>"}, None, None),
        ("traversal", attack, "GET", "/api/version/info", {"q": "../../../../etc/passwd"}, None, None),
        ("traversal_encoded", attack, "GET", "/api/version/info", {"q": "..%2f..%2f..%2fetc/passwd"}, None, None),
        ("cmd_semicolon", attack, "GET", "/api/version/info", {"q": "; cat /etc/passwd"}, None, None),
        ("cmd_subshell", attack, "GET", "/api/version/info", {"q": "$(whoami)"}, None, None),
        ("cmd_backtick", attack, "GET", "/api/version/info", {"q": "`id`"}, None, None),
        ("ssrf_metadata", attack, "GET", "/api/version/info", {"q": "http://169.254.169.254/latest/meta-data/"}, None, None),
        ("benign_plain", benign, "GET", "/api/version/info", None, None, None),
        ("benign_param", benign, "GET", "/api/version/info", {"q": "hello world"}, None, None),
        ("benign_home", benign, "GET", "/", None, None, None),
        ("post_sql_json", post_only, "POST", "/api/auth/login", None,
         json.dumps({"username": "admin' OR '1'='1", "password": "x"}), {"Content-Type": "application/json"}),
        ("post_multipart", post_only, "POST", "/api/auth/upload-avatar", None,
         multipart_body(), {"Content-Type": "multipart/form-data; boundary=----ironwall"}),
    ]
    return entries


def multipart_body():
    boundary = "----ironwall"
    payload = "admin' OR '1'='1.png"
    content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8
    parts = []
    parts.append("--" + boundary)
    parts.append("Content-Disposition: form-data; name=\"avatar\"; filename=\"%s\"" % payload)
    parts.append("Content-Type: image/png")
    parts.append("")
    parts.append("")
    body = ("\r\n".join(parts)).encode("utf-8") + content
    body += ("\r\n--" + boundary + "--\r\n").encode("utf-8")
    return body


def perform(base, entry, timeout):
    name, kind, method, path, params, body, headers = entry
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = body
    if isinstance(body, str):
        data = body.encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("User-Agent", UA)
    if headers:
        for key, value in headers.items():
            request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, b""
    except urllib.error.HTTPError as error:
        return error.code, error.read(512)
    except Exception as error:  # connection failures count as defense engaged for attack tests
        return 0, str(error).encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="IronWall black-box regression matrix")
    parser.add_argument("--list-only", action="store_true",
                        help="print the matrix without sending any request")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="per-request timeout in seconds (default 10)")
    parser.add_argument("--include-post", action="store_true",
                        help="include POST multipart/JSON probe entries")
    parser.add_argument("--strict-benign", action="store_true",
                        help="treat any non-200 benign response as a failure")
    args = parser.parse_args()

    base = os.environ.get("IRONWALL_BASE_URL", DEFAULT_BASE)
    matrix = [entry for entry in build_matrix()
              if entry[1] != "post" or args.include_post]

    if args.list_only:
        print("base: %s" % base)
        for name, kind, method, path, params, body, headers in matrix:
            print("%-22s %-8s %s %s%s" % (name, kind, method, path,
                                          ("?" + urllib.parse.urlencode(params)) if params else ""))
        return 0

    misses = []
    warnings = []
    blocked_count = 0
    benign_ok = 0
    for entry in matrix:
        name, kind, method, path, params, body, headers = entry
        status, _ = perform(base, entry, args.timeout)
        if kind == "benign":
            if status == 200:
                benign_ok += 1
                print("[OK  ] %-22s benign 200" % name)
            else:
                warnings.append((name, status))
                print("[WARN] %-22s benign got %s (environmental, not a leak)" % (name, status))
        else:
            if status in BLOCK_STATUS:
                blocked_count += 1
                print("[OK  ] %-22s blocked %s" % (name, status))
            else:
                misses.append((name, status))
                print("[MISS] %-22s returned %s (engine must block this)" % (name, status))

    print("-" * 60)
    print("summary: blocked=%d benign_ok=%d misses=%d warnings=%d"
          % (blocked_count, benign_ok, len(misses), len(warnings)))
    if warnings and args.strict_benign:
        print("FAIL: --strict-benign set and %d benign probes were disturbed" % len(warnings))
        return 1
    if misses:
        print("FAIL: %d attack payload(s) reached the application" % len(misses))
        return 1
    print("PASS: every attack payload was intercepted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
