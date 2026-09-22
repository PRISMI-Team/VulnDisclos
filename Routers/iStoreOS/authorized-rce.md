# iStoreOS router authenticated command splicing RCE (CVE-2026-78797)

## Summary
The application fails to properly validate and sanitize user-controlled input before incorporating it into a system command. An authenticated attacker can craft malicious input to alter the intended command execution flow, potentially achieving arbitrary command execution and remote code execution on the affected system.


## Affected Product
- Vendor: iStoreOS
- Product: iStoreOS
- Affected Versions:istoreos-24.10.7 and before


## Timeline
- 2026/5/9 - Vulnerability discovered during security testing of the iStoreOS router.
- 2026/6/12 - Requests to MITRE for CVE.
- 2026/9/14 - Publicly disclosed
