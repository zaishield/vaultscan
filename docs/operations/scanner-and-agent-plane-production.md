# External Scanner Plane + Internal Agent Plane — production runbook

Closes the four SEV-1/SEV-2 items from the plane audit:

| # | Gap | Now |
|---|---|---|
| 1 | Worker used `exec.CommandContext`, not K8s Jobs | `K8sJobRunner` submits per-tool batch/v1 Jobs |
| 2 | No scanner-worker Helm template | `scanner-worker-deployment.yaml` + `scanner-worker-rbac.yaml` |
| 3 | Scanner images unsigned + unpinned | `scanner-image-sign-and-pin` workflow + `digests.json` |
| 4 | Agent had no signed installer | GoReleaser deb/rpm + Windows MSI + macOS notarized pkg |

## Scanner plane — operational layout

```
control-plane namespace
  ┌─────────────────────────────────┐
  │ scanner-worker-<region>         │  (one Deployment per region)
  │   reads scan_jobs WHERE plane=  │
  │     'external' AND region=<r>   │
  │   verifies RSA-PSS job sig      │
  │   verifies cosign image sig     │
  │   submits batch/v1 Job          ├──┐
  └─────────────────────────────────┘  │
                                       ▼
scanner-<region> namespace             (per-region tool sandbox)
  ┌─────────────────────────────────┐
  │  Job: vs-nmap-abc123             │
  │   pod: scanner-tool SA           │
  │   container: registry/nmap@sha256:...   ← digest-pinned + cosigned
  │     non-root, readOnlyRootFS,    │
  │     drop ALL caps, seccomp       │
  │     resources req/lim CPU/mem    │
  │     activeDeadlineSeconds        │
  │     NetworkPolicy: DNS only +    │
  │       operator-defined egress    │
  └─────────────────────────────────┘
```

### Enabling

```yaml
# values.production.yaml
scannerWorker:
  enabled: true
  runner:  k8s
  imageRegistry: ghcr.io/zaishield/vaultscan/scanners
  requireSignedImages: "true"
  regions:
    - { name: us-east-1, replicaCount: 3 }
    - { name: eu-west-1, replicaCount: 2 }
  networkPolicyEgress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16]
      # Allow internet; deny RFC1918 + metadata service.
```

The chart creates one `scanner-<region>` namespace per regions entry,
each with:
- a `scanner-tool` ServiceAccount with NO permissions (defense in depth)
- a `Role` + `RoleBinding` granting the cross-namespace
  `scanner-worker` SA the minimum it needs (create/get/delete jobs +
  read pods/log)
- a default `NetworkPolicy` denying inbound, permitting DNS + the
  operator-defined egress list

### Verifying

```bash
kubectl -n vaultscan get deploy -l app.kubernetes.io/component=scanner-worker
kubectl -n scanner-us-east-1 get jobs    # active per-tool Jobs
kubectl -n scanner-us-east-1 get pods -l app.kubernetes.io/component=scanner-tool
```

A scan job submission appears as a `Job` named `vs-<tool>-<8 hex>`
in the matching `scanner-<region>` namespace. The job's `tmp`
emptyDir is sized at 1Gi; tools that need more storage need
operator overrides.

### Image digest pinning

`tools/scanner-images/digests.json` maps every scanner tool to its
immutable digest. The `scanner-image-sign-and-pin` CI workflow:

1. Builds + pushes each scanner image to ghcr.io on every `v*` tag.
2. Captures the manifest digest from `docker buildx imagetools inspect`.
3. Signs the image at the digest reference (`<img>@sha256:<digest>`)
   with cosign keyless using the GHA OIDC token.
4. `scanner-digests-aggregate` consolidates the per-tool digests into
   `digests.json`, commits + pushes back to main.

The API loads `digests.json` at boot (`scanorch.NewImageDigestRegistry`)
and the orchestrator's task materialiser writes
`<registry>/<tool>@sha256:<digest>` into `scan_tasks.image_ref`. If
the file is missing or empty (dev cluster, no tag pushed yet) the
chart falls back to mutable `:latest` references + logs a warning.

Run `kubectl describe pod` on a tool pod — the image should resolve
to the SHA reference, not the `latest` tag.

## Agent plane — installer ecosystem

### Building a release

```bash
git tag v1.4.0
git push --tags
```

GitHub Actions then:
1. `goreleaser` builds linux + darwin + windows binaries with the
   cloud public key embedded via `-X main.embeddedCloudPubKeyB64`.
2. nfpm wraps the linux binaries into `.deb` + `.rpm` packages with
   a systemd unit + pre/postinstall scripts.
3. `windows-msi` job runs on a windows-2022 runner: wix builds the
   MSI, signtool signs it with the EV cert, cosign signs the .msi as
   a blob.
4. `macos-pkg` job runs on macos-14 (arm64 + amd64 matrix):
   pkgbuild → productsign → notarytool → stapler → cosign.
5. All artifacts uploaded to the GitHub release; cosign bundles
   alongside.

### Install — Linux

```bash
# deb-based:
curl -LO https://github.com/zaishield/vaultscan/releases/download/v1.4.0/vaultscan-agent_1.4.0_linux_amd64.deb
curl -LO https://github.com/zaishield/vaultscan/releases/download/v1.4.0/vaultscan-agent_1.4.0_linux_amd64.deb.cosign.bundle

# Verify before installing:
cosign verify-blob \
  --certificate-identity-regexp='https://github.com/zaishield/vaultscan/.*' \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --bundle vaultscan-agent_1.4.0_linux_amd64.deb.cosign.bundle \
  vaultscan-agent_1.4.0_linux_amd64.deb

sudo apt install ./vaultscan-agent_1.4.0_linux_amd64.deb

# Fill in tenant_id / agent_id / gateway_url / enrolment_token:
sudo vi /etc/vaultscan-agent/agent.yaml

sudo systemctl enable --now vaultscan-agent
sudo journalctl -u vaultscan-agent -f
```

The systemd unit ships with hardening: `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, full seccomp
filter, no capabilities. State lives in `/var/lib/vaultscan-agent`
(systemd's `StateDirectory=`).

### Install — Windows

Run `vaultscan-agent.msi`. The MSI is dual-signed (Authenticode + cosign).
Service registers as "VAULTSCAN Agent" set to auto-start. Config at
`C:\ProgramData\VAULTSCAN\agent\agent.yaml`. The postinstall script
refuses to start until placeholders are filled.

### Install — macOS

Run the `.pkg`. Both `productsign`-signed AND notarized; Gatekeeper
won't prompt. Daemon launches via launchd; plist at
`/Library/LaunchDaemons/com.zaishield.vaultscan-agent.plist`. Logs
in `/var/log/vaultscan-agent/`.

### Upgrading

The cloud's `/api/v1/agents/{id}/update-offer` endpoint serves the
latest signed update bundle. The agent's `updater` package polls this,
verifies the manifest's RSA signature, and writes the new binary
atomically (`rename` after `fsync`). No OS package-manager
involvement for in-place upgrades.

For policy changes that require a full re-install (signing-cert
rotation, OS-level config), operators push the new `.deb`/`.rpm`/
`.msi`/`.pkg` via their fleet manager (Ansible, Tanium, Intune, MDM).

### Verifying signatures at runtime

The agent's `verifier` package refuses to run any job whose RSA-PSS
signature doesn't match the embedded cloud public key. To verify the
binary itself was the one CI shipped:

```bash
cosign verify-blob \
  --certificate-identity-regexp='https://github.com/zaishield/vaultscan/.*' \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --bundle vaultscan-agent_1.4.0_linux_amd64.deb.cosign.bundle \
  vaultscan-agent_1.4.0_linux_amd64.deb
```

Failure = the artifact was modified post-build OR signed by
something other than the expected GH Actions workflow.

## SLO targets (now achievable)

| SLO | Target | How |
|---|---|---|
| Scanner-job dispatch latency | p95 ≤ 2s | claim → K8s Job created |
| Per-tool isolation | 100% | each tool runs in its own Pod |
| Image supply-chain integrity | 100% | cosign verify on every Job pod |
| Agent emergency-stop ack | p95 ≤ 30s | unchanged (heartbeat ack flow) |
| Agent installer signature verifiable | 100% | cosign bundle alongside every artifact |
| Cloud key rotation propagation | 1 release | rebuild + roll out new binaries |
