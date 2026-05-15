// gcp_controls_extended.go — additional CIS-GCP controls beyond the
// initial 4 in gcp_adapter.go.
package cloudposture

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

func (a *GCPAdapter) extendedScans(ctx context.Context, c GCPCredentials, tok string) []ControlResult {
	var out []ControlResult
	// IAM
	out = append(out, a.checkPrimitiveRolesUnused(ctx))
	out = append(out, a.checkExternalServiceAccountKeysRotated(ctx))
	out = append(out, a.checkSAUserManagedKeys(ctx))
	out = append(out, a.checkOrgPolicyDomainRestricted(ctx))
	// Logging
	out = append(out, a.checkLoggingMetricsForOwnership(ctx))
	out = append(out, a.checkLogRouterToBigQuery(ctx))
	out = append(out, a.checkVPCFlowLogs(ctx))
	// Storage
	out = append(out, a.checkStorageRetentionPolicy(ctx, c, tok)...)
	out = append(out, a.checkStorageVersioningEnabled(ctx, c, tok)...)
	out = append(out, a.checkStorageBucketLogging(ctx))
	// Compute
	out = append(out, a.checkComputeBlockProjectSSHKeys(ctx, c, tok)...)
	out = append(out, a.checkComputeShieldedVMEnabled(ctx))
	out = append(out, a.checkComputeOSLoginEnabled(ctx))
	out = append(out, a.checkComputeIPForwardingDisabled(ctx))
	out = append(out, a.checkSerialPortDisabled(ctx))
	// Network
	out = append(out, a.checkFirewallRDP(ctx, c, tok)...)
	out = append(out, a.checkDefaultNetworkUnused(ctx))
	out = append(out, a.checkPrivateGoogleAccess(ctx))
	out = append(out, a.checkVPCSCEnabled(ctx))
	// SQL / Spanner
	out = append(out, a.checkCloudSQLPublicIP(ctx))
	out = append(out, a.checkCloudSQLBackupsEnabled(ctx))
	out = append(out, a.checkCloudSQLPrivateService(ctx))
	out = append(out, a.checkCloudSQLSSLRequired(ctx))
	// KMS
	out = append(out, a.checkKMSRotationDays(ctx))
	out = append(out, a.checkKMSPublicAccess(ctx))
	// GKE
	out = append(out, a.checkGKEClusterPrivate(ctx))
	out = append(out, a.checkGKEAutoUpgrade(ctx))
	out = append(out, a.checkGKEBinaryAuthorization(ctx))
	out = append(out, a.checkGKEWorkloadIdentity(ctx))
	out = append(out, a.checkGKEMasterAuthorizedNetworks(ctx))
	return out
}

// ----- IAM ----------------------------------------------------------------

func (a *GCPAdapter) checkPrimitiveRolesUnused(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-1.4", "Primitive (Owner/Editor/Viewer) roles unused",
		"Audit roles via gcloud projects get-iam-policy; replace with predefined/custom roles.")
}

func (a *GCPAdapter) checkExternalServiceAccountKeysRotated(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-1.7", "External SA keys rotated within 90 days",
		"Audit gcloud iam service-accounts keys list --iam-account=<sa>.")
}

func (a *GCPAdapter) checkSAUserManagedKeys(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-1.5", "User-managed SA keys not used",
		"Use Workload Identity Federation instead of long-lived SA keys.")
}

func (a *GCPAdapter) checkOrgPolicyDomainRestricted(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-1.18", "iam.allowedPolicyMemberDomains org policy set",
		"gcloud resource-manager org-policies set-policy <policy.yaml>")
}

// ----- Logging ------------------------------------------------------------

func (a *GCPAdapter) checkLoggingMetricsForOwnership(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-2.4.1", "Log metrics + alerts for project ownership changes",
		"gcloud logging metrics create owner-change ...")
}

func (a *GCPAdapter) checkLogRouterToBigQuery(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-2.2", "Logging sinks to BigQuery for analytics",
		"gcloud logging sinks create bq-export bigquery.googleapis.com/projects/<p>/datasets/<d>")
}

func (a *GCPAdapter) checkVPCFlowLogs(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-3.8", "VPC flow logs enabled on all subnets",
		"gcloud compute networks subnets update <sn> --enable-flow-logs")
}

// ----- Storage ------------------------------------------------------------

func (a *GCPAdapter) checkStorageRetentionPolicy(ctx context.Context, c GCPCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s&projection=full", c.ProjectID)
	body, err := a.gcpGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-GCP-5.2",
			"Storage bucket: retention policy locked", "storage.bucket", err)}
	}
	type bucket struct {
		Name              string `json:"name"`
		Location          string `json:"location"`
		RetentionPolicy   *struct {
			RetentionPeriod int  `json:"retentionPeriod,string"`
			IsLocked        bool `json:"isLocked"`
		} `json:"retentionPolicy"`
	}
	type listing struct {
		Items []bucket `json:"items"`
	}
	var l listing
	_ = json.Unmarshal(body, &l)
	var out []ControlResult
	for _, b := range l.Items {
		ctrl := ControlResult{
			ControlID: "CIS-GCP-5.2", Title: "Storage bucket: retention policy locked",
			Severity: "medium", Region: b.Location, Resource: "gs://" + b.Name,
			Remediation: "gsutil retention set <duration> gs://" + b.Name + "; gsutil retention lock gs://" + b.Name,
		}
		if b.RetentionPolicy != nil && b.RetentionPolicy.IsLocked {
			ctrl.Status = "pass"
		} else if b.RetentionPolicy != nil {
			ctrl.Status = "fail"
			ctrl.Evidence = "retention policy not locked"
		} else {
			ctrl.Status = "fail"
			ctrl.Evidence = "no retention policy configured"
		}
		out = append(out, ctrl)
	}
	return out
}

func (a *GCPAdapter) checkStorageVersioningEnabled(ctx context.Context, c GCPCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s&projection=full", c.ProjectID)
	body, err := a.gcpGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-GCP-5.3",
			"Storage bucket: object versioning enabled", "storage.bucket", err)}
	}
	type bucket struct {
		Name       string `json:"name"`
		Location   string `json:"location"`
		Versioning *struct {
			Enabled bool `json:"enabled"`
		} `json:"versioning"`
	}
	type listing struct {
		Items []bucket `json:"items"`
	}
	var l listing
	_ = json.Unmarshal(body, &l)
	var out []ControlResult
	for _, b := range l.Items {
		ctrl := ControlResult{
			ControlID: "CIS-GCP-5.3", Title: "Storage bucket: object versioning enabled",
			Severity: "low", Region: b.Location, Resource: "gs://" + b.Name,
			Remediation: "gsutil versioning set on gs://" + b.Name,
		}
		if b.Versioning != nil && b.Versioning.Enabled {
			ctrl.Status = "pass"
		} else {
			ctrl.Status = "fail"
			ctrl.Evidence = "versioning not enabled"
		}
		out = append(out, ctrl)
	}
	return out
}

func (a *GCPAdapter) checkStorageBucketLogging(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-2.4", "Storage bucket: access logging enabled",
		"gsutil logging set on -b gs://<log-bucket> gs://<bucket>")
}

// ----- Compute ------------------------------------------------------------

func (a *GCPAdapter) checkComputeBlockProjectSSHKeys(ctx context.Context, c GCPCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/aggregated/instances", c.ProjectID)
	body, err := a.gcpGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-GCP-4.2",
			"Block project-wide SSH keys on instances", "compute.instance", err)}
	}
	type item struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	type metadata struct {
		Items []item `json:"items"`
	}
	type instance struct {
		Name     string   `json:"name"`
		Zone     string   `json:"zone"`
		Metadata metadata `json:"metadata"`
	}
	type zoneList struct {
		Instances []instance `json:"instances"`
	}
	type aggregated struct {
		Items map[string]zoneList `json:"items"`
	}
	var a2 aggregated
	_ = json.Unmarshal(body, &a2)
	var out []ControlResult
	for _, zl := range a2.Items {
		for _, inst := range zl.Instances {
			ctrl := ControlResult{
				ControlID: "CIS-GCP-4.2", Title: "Block project-wide SSH keys on instances",
				Severity: "medium", Region: shortZone(inst.Zone), Resource: inst.Name,
				Remediation: "gcloud compute instances add-metadata " + inst.Name + " --metadata block-project-ssh-keys=true",
			}
			ctrl.Status = "fail"
			ctrl.Evidence = "block-project-ssh-keys metadata not set"
			for _, m := range inst.Metadata.Items {
				if m.Key == "block-project-ssh-keys" && strings.EqualFold(m.Value, "true") {
					ctrl.Status = "pass"
					ctrl.Evidence = ""
					break
				}
			}
			out = append(out, ctrl)
		}
	}
	if len(out) == 0 {
		return []ControlResult{{
			ControlID: "CIS-GCP-4.2", Title: "Block project-wide SSH keys on instances",
			Severity: "medium", Status: "not_applicable", Evidence: "no Compute instances",
		}}
	}
	return out
}

func (a *GCPAdapter) checkComputeShieldedVMEnabled(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-4.8", "Compute instances: Shielded VM enabled",
		"gcloud compute instances update <name> --shielded-secure-boot --shielded-vtpm")
}

func (a *GCPAdapter) checkComputeOSLoginEnabled(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-4.4", "Compute: OS Login enabled at project level",
		"gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE")
}

func (a *GCPAdapter) checkComputeIPForwardingDisabled(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-4.6", "Compute instances: IP forwarding disabled",
		"Recreate instance with --no-can-ip-forward.")
}

func (a *GCPAdapter) checkSerialPortDisabled(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-4.5", "Compute instances: serial port disabled",
		"gcloud compute instances add-metadata <name> --metadata serial-port-enable=FALSE")
}

// ----- Network ------------------------------------------------------------

func (a *GCPAdapter) checkFirewallRDP(ctx context.Context, c GCPCredentials, tok string) []ControlResult {
	// Adapted from checkFirewallSSH but for port 3389.
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/global/firewalls", c.ProjectID)
	body, err := a.gcpGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-GCP-3.7",
			"No firewall rule allowing RDP (3389) from 0.0.0.0/0", "compute.firewall", err)}
	}
	type allowed struct {
		IPProtocol string   `json:"IPProtocol"`
		Ports      []string `json:"ports"`
	}
	type rule struct {
		Name         string    `json:"name"`
		Direction    string    `json:"direction"`
		Disabled     bool      `json:"disabled"`
		SourceRanges []string  `json:"sourceRanges"`
		Allowed      []allowed `json:"allowed"`
	}
	type listing struct {
		Items []rule `json:"items"`
	}
	var l listing
	_ = json.Unmarshal(body, &l)
	var violations []string
	for _, r := range l.Items {
		if r.Disabled || strings.ToUpper(r.Direction) != "INGRESS" {
			continue
		}
		hasAny := false
		for _, s := range r.SourceRanges {
			if strings.TrimSpace(s) == "0.0.0.0/0" {
				hasAny = true
				break
			}
		}
		if !hasAny {
			continue
		}
		for _, alw := range r.Allowed {
			if !strings.EqualFold(alw.IPProtocol, "tcp") && alw.IPProtocol != "all" {
				continue
			}
			for _, p := range alw.Ports {
				if p == "3389" {
					violations = append(violations, r.Name+":3389")
					break
				}
			}
		}
	}
	ctrl := ControlResult{
		ControlID: "CIS-GCP-3.7", Title: "No firewall rule allowing RDP (3389) from 0.0.0.0/0",
		Severity: "high", Resource: "compute.firewall:" + c.ProjectID,
		Remediation: "Restrict source ranges via gcloud compute firewall-rules update.",
	}
	if len(violations) == 0 {
		ctrl.Status = "pass"
	} else {
		ctrl.Status = "fail"
		ctrl.Evidence = "violating rules: " + strings.Join(violations, ",")
	}
	return []ControlResult{ctrl}
}

func (a *GCPAdapter) checkDefaultNetworkUnused(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-3.1", "Default VPC network deleted",
		"gcloud compute networks delete default")
}

func (a *GCPAdapter) checkPrivateGoogleAccess(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-3.4", "Subnets: Private Google Access enabled",
		"gcloud compute networks subnets update <sn> --enable-private-ip-google-access")
}

func (a *GCPAdapter) checkVPCSCEnabled(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-3.10", "VPC Service Controls perimeter enabled",
		"Configure Access Context Manager + VPC SC perimeter for sensitive APIs.")
}

// ----- SQL ----------------------------------------------------------------

func (a *GCPAdapter) checkCloudSQLPublicIP(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-6.6", "Cloud SQL: no public IP",
		"Disable public IP on every instance; use Cloud SQL Auth proxy.")
}

func (a *GCPAdapter) checkCloudSQLBackupsEnabled(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-6.7", "Cloud SQL: automated backups enabled",
		"gcloud sql instances patch <inst> --backup-start-time HH:MM")
}

func (a *GCPAdapter) checkCloudSQLPrivateService(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-6.8", "Cloud SQL: Private Service Connect",
		"Enable PSC for least exposure.")
}

func (a *GCPAdapter) checkCloudSQLSSLRequired(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-6.4", "Cloud SQL: require SSL/TLS for connections",
		"gcloud sql instances patch <inst> --require-ssl")
}

// ----- KMS ----------------------------------------------------------------

func (a *GCPAdapter) checkKMSRotationDays(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-1.10", "KMS keys: rotation period ≤ 90 days",
		"gcloud kms keys update --rotation-period 7776000s --next-rotation-time +90d")
}

func (a *GCPAdapter) checkKMSPublicAccess(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-1.9", "KMS keys: not publicly accessible",
		"Audit IAM bindings; remove allUsers / allAuthenticatedUsers.")
}

// ----- GKE ----------------------------------------------------------------

func (a *GCPAdapter) checkGKEClusterPrivate(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-7.6", "GKE clusters: private nodes",
		"Recreate cluster with --enable-private-nodes.")
}

func (a *GCPAdapter) checkGKEAutoUpgrade(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-7.13", "GKE node pools: auto-upgrade enabled",
		"gcloud container node-pools update <pool> --enable-autoupgrade")
}

func (a *GCPAdapter) checkGKEBinaryAuthorization(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-7.16", "GKE: Binary Authorization enabled",
		"gcloud container clusters update --binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE")
}

func (a *GCPAdapter) checkGKEWorkloadIdentity(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-7.18", "GKE: Workload Identity enabled",
		"gcloud container clusters update --workload-pool=<project>.svc.id.goog")
}

func (a *GCPAdapter) checkGKEMasterAuthorizedNetworks(_ context.Context) ControlResult {
	return gcpManual("CIS-GCP-7.4", "GKE: master authorized networks restricted",
		"gcloud container clusters update --enable-master-authorized-networks --master-authorized-networks <CIDR>")
}

// ----- helpers ------------------------------------------------------------

func gcpManual(id, title, remediation string) ControlResult {
	return ControlResult{
		ControlID: id, Title: title, Severity: "medium",
		Status: "manual", Remediation: remediation,
		Evidence: "automated check not implemented; verify in GCP Console",
	}
}
