# Phishing Email Analysis Report
**Analyst:** Mukul  
**Date:** 21 June 2026  
**Sample:** sample-10.eml  
**Severity:** High  

---

## 1. Executive Summary

A phishing email impersonating Microsoft was analyzed from the `rf-peixoto/phishing_pot` public repository. The email claimed to alert the recipient about unusual sign-in activity on their Microsoft account. Investigation revealed multiple authentication failures, a spoofed sender domain, an attacker-controlled redirect URL, and infrastructure hosted on a Polish ISP. The URL was flagged by 10 out of 92 security vendors on VirusTotal as phishing or malicious. Both attacker domains are now unregistered, consistent with a hit-and-run phishing campaign.

---

## 2. Email Metadata

| Field | Value |
|---|---|
| Subject | Microsoft account unusual signin activity |
| From | Microsoft account team `<no-reply@access-accsecurity.com>` |
| To | phishing@pot |
| Date | Fri, 8 Sep 2023 — 05:47:04 +0000 |
| Reply-To | sotrecognizd@gmail.com |
| Return-Path | bounce@thcultarfdes.co.uk |
| Content-Type | text/html; charset=UTF-8 |
| Content-Transfer-Encoding | 8bit |

---

## 3. Header Analysis

### 3.1 Authentication Results

| Check | Result | Meaning |
|---|---|---|
| SPF | `none` | Sending domain has no SPF record |
| DKIM | `none` | Email is not digitally signed |
| DMARC | `permerror` | DMARC check failed with permanent error |

All three email authentication mechanisms failed. A legitimate Microsoft email would pass all three.

### 3.2 Sender Mismatch (Red Flag)

| Field | Value |
|---|---|
| From | `no-reply@access-accsecurity.com` |
| Return-Path | `bounce@thcultarfdes.co.uk` |
| Reply-To | `sotrecognizd@gmail.com` |

Three different domains across three fields — a strong indicator of email spoofing. Legitimate senders use the same domain consistently.

### 3.3 Email Hop Chain

The `Received: from` headers read bottom-up to trace the real origin:

```
[1] thcultarfdes.co.uk (89.144.44.2)         ← REAL ORIGIN — attacker server
        ↓
[2] DB8EUR06FT032.eop-eur06.prod.outlook.com  ← Microsoft spam filter
        ↓
[3] DB8P191CA0014.EURP191.PROD.OUTLOOK.COM    ← Microsoft relay
        ↓
[4] SJ0PR19MB6679.namprd19.prod.outlook.com   ← Final delivery
```

The email entered Microsoft's infrastructure from `thcultarfdes.co.uk` hosted at `89.144.44.2`.

---

## 4. URL Analysis

### 4.1 Extracted URL

```
http://thebandalisty.com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176
```

This is a tracking and redirect URL. When clicked by a victim, it would:
- Notify the attacker that the link was clicked
- Redirect the victim to a credential harvesting page

### 4.2 VirusTotal Result

| Metric | Value |
|---|---|
| Detection | 10 / 92 vendors flagged as malicious |
| Category | Phishing / Malicious |
| Last Scan | 3 days before analysis |

Vendors flagging as malicious: ADMINUSLabs, alphaMountain.ai, BitDefender, CRDF, CyRadar, Fortinet, G-Data, Lionic, Sophos, Webroot.

---

## 5. IP Intelligence

| Field | Value |
|---|---|
| IP Address | 89.144.44.2 |
| Location | Warsaw, Mazovia, Poland |
| ASN | AS201132 |
| ISP | MSCode.pl |
| Hostname | r2.mscode.pl |
| Type | ISP — not a VPN or proxy |
| Abuse Contact | abuse@ghostnet.de |

Microsoft has no legitimate infrastructure at this IP. This is attacker-controlled hosting.

---

## 6. WHOIS Analysis

| Domain | WHOIS Result | Interpretation |
|---|---|---|
| thcultarfdes.co.uk | Not registered | Domain deleted post-campaign |
| thebandalisty.com | Not registered | Domain deleted post-campaign |

Attacker registered temporary domains, conducted the phishing campaign, then dropped the domains — a common technique to evade long-term blacklisting and attribution.

---

## 7. IOC Summary

| Type | Indicator |
|---|---|
| Email | no-reply@access-accsecurity.com |
| Email | sotrecognizd@gmail.com |
| Email | bounce@thcultarfdes.co.uk |
| Domain | access-accsecurity.com |
| Domain | thcultarfdes.co.uk |
| Domain | thebandalisty.com |
| IP | 89.144.44.2 |
| URL | http://thebandalisty.com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176 |

---

## 8. MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Link | Malicious redirect URL embedded in email body |
| T1036.005 | Masquerading: Match Legitimate Name | `access-accsecurity.com` impersonating Microsoft |
| T1598 | Phishing for Information | Fake Microsoft security alert to steal credentials |
| T1078 | Valid Accounts (target) | Microsoft account login flow being impersonated |

---

## 9. Analyst Recommendations

If this email were received in a live SOC environment:

| Priority | Action |
|---|---|
| Immediate | Block sender domain `access-accsecurity.com` at email gateway |
| Immediate | Block IP `89.144.44.2` at perimeter firewall |
| Immediate | Block domain `thebandalisty.com` at web proxy |
| High | Search mail logs for other recipients of this campaign |
| High | Identify any users who clicked the link — force password reset |
| Medium | Submit all IOCs to threat intel platform (MISP / OpenCTI) |
| Medium | Create detection rule in SIEM for similar patterns |

### Detection Rule (Splunk)

```spl
index=email_logs
(from="*accsecurity*" OR return_path="*thcultarfdes*" OR src_ip="89.144.44.2")
| table _time, from, subject, src_ip, return_path
| sort - _time
```

---

## 10. Screenshots

| # | File | Description |
|---|---|---|
| 1 | screenshots/eml-file-in-thunderbird.png | Phishing email in Thunderbird — remote content blocked |
| 2 | screenshots/eml-files.png | phishing_pot sample files |
| 3 | screenshots/raw-headers.png | Raw email headers in Thunderbird View Source |
| 4 | screenshots/header-extract.png | Header grep output in Ubuntu terminal |
| 5 | screenshots/originating-ip.png | Email hop chain — real sender identified |
| 6 | screenshots/content-and-urls.png | URL extracted from email body |
| 7 | screenshots/ip-lookup.png | ipinfo.io — IP traced to Warsaw, Poland |
| 8 | screenshots/virus-total.png | VirusTotal — 10/92 detections |
| 9 | screenshots/who-is.png | WHOIS — both domains unregistered |

---

*This analysis was conducted in an isolated lab environment for educational and portfolio purposes only.*
