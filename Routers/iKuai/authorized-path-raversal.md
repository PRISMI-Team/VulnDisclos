# iKuai router authorized path raversal RCE(CVE-2026-78799)

## Summary

The application insufficiently validates user-controlled file paths, allowing an authenticated attacker to manipulate path parameters and access locations outside the intended directory.

## Affected Product
- Vendor: iKuai
- Product: IK-Q3000
- Affected Versions: 
    - Enterprise Edition: <= iKuai8_3.7.23_Enterprise Build 202606021825 
    - Free Edition: <= iKuai 8_4.0.304-beta

## Timeline
- 2026/5/13 - Vulnerability discovered during security testing of the iKuai router.
- 2026/6/12 - Requests to MITRE for CVE.
- 2026/9/14 - Publicly disclosed
