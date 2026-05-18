# Runbook — Kyverno policy violation

## Symptom

A Deployment / Pod / Job creation is rejected with `AdmissionReview`
failure. Operator sees in `kubectl describe`:

```
Error from server: admission webhook "validate.kyverno.svc-fail" denied the request:
  resource Pod/default/vaultscan-api-xyz was blocked due to the following policies:
    require-signed-images:
      check-image: |
        unsigned image: registry.zaishield.com/vaultscan/api:1.2.0
```

## Initial triage

| Symptom variant | Most likely cause |
| --- | --- |
| `check-image: unsigned image` | Image was pushed without cosign-sign; tag was mutated post-sign; Kyverno can't reach Sigstore |
| `runAsNonRoot must be true` | Pod spec missing security context; scanner-tool override map mismatch |
| `host network not allowed` | Privileged scanner (kube-bench) routed to wrong namespace |
| `disallowed capability` | Tool that needs NET_RAW dispatched without the cap in its `toolCapabilityAdds` entry |

## Immediate steps

1. **Identify the policy + resource**

```bash
kubectl get clusterpolicies
kubectl get pol -A
kubectl describe pol -n <ns> <policy-name>
kubectl get events -A | grep -i "kyverno\|policy"
```

2. **Confirm the rejection is correct**

If the policy is doing its job (an actually unsigned image / a pod
that should be non-root): **DO NOT bypass the policy**. Fix the
underlying issue.

If the policy is wrong (e.g. cosign cert chain rotated; legitimate
tool flagged): proceed to bypass while you fix.

## Bypass (audit-mode only)

```bash
# Switch the offending policy to `audit` mode for 1 hour to unblock
# the deployment. The 1-hour boundary is what you commit to fixing
# inside.
kubectl patch cpol require-signed-images --type=merge \
  -p '{"spec":{"validationFailureAction":"Audit"}}'

# Set a calendar reminder; revert to Enforce within the hour.
```

## Root-cause: unsigned image

If the failure is `unsigned image`:

1. Look up the image in the registry — is the cosign signature
   attached? `cosign verify --certificate-identity-regexp ... <img>`
2. If unsigned: re-run the release workflow (`gh workflow run
   security.yml --ref v1.2.0`) to generate the missing signature.
3. If signed but verification fails: check whether the cosign cert
   chain was rotated (`docs/operations/cosign-key-rotation.md`).
4. If Sigstore is unreachable: surface as P0 incident (every
   deployment is now blocked).

## Root-cause: pod-security policy

1. Check `internal/scanner/runner_k8s_tool_security.go` for the tool's entry.
2. If the tool needs an elevation, add to one of the maps:
   - `rootContainerTools` (runAsNonRoot: false)
   - `toolCapabilityAdds` (NET_RAW etc.)
   - `hostNetworkTools` / `hostPIDTools`
3. Rebuild + redeploy the scanner-worker. The orchestrator picks up
   the change on next dispatch.

## Don'ts

- **Do NOT** `kubectl patch ... type: Audit` on `require-signed-images`
  in production and leave it that way. Unsigned-image-acceptance is
  the path to a supply-chain incident.
- **Do NOT** add `kyverno.io/exclude: "true"` to a Deployment to
  bypass a policy. The exclude removes the entire policy class from
  that deployment — usually broader than you intended.
- **Do NOT** delete the policy. Always patch + revert.

## Postmortem questions

- Was the policy itself wrong, or was the resource? Document.
- Can we add a CI check that catches this before deploy?
- Should this policy be in our test-cluster CI matrix?

## Related
- `cosign-key-rotation.md`
- `scanner-image-release.md`
- `pentest-engagement-runbook.md`
