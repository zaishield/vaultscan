// gcp_adapter.go — GCP ProviderAdapter using the GCP REST APIs
// authenticated via a service-account JSON key. The service account
// JWT flow:
//
//   1. Build a JWT:
//        header  = {"alg":"RS256","typ":"JWT","kid":<private_key_id>}
//        payload = {"iss":<client_email>, "scope":<space-joined OAuth scopes>,
//                   "aud":"https://oauth2.googleapis.com/token",
//                   "iat":now, "exp":now+1h}
//        sig     = RSA-SHA256(headerb64+"."+payloadb64, private_key)
//
//   2. POST it to https://oauth2.googleapis.com/token as
//        grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
//        assertion=<jwt>
//
//   3. Receive {access_token, expires_in}; cache for ~5 min.
//
//   4. Send Authorization: Bearer <token> on every API call.
//
// Controls implemented:
//   * CIS-GCP-5.1   Storage bucket: uniform bucket-level access enabled
//                   (storage.googleapis.com/storage/v1/b/?project=...)
//   * CIS-GCP-1.4   Default Compute Engine SA not used
//                   (iam.googleapis.com/v1/projects/<p>/serviceAccounts)
//   * CIS-GCP-3.6   No firewall rule allowing 22 from 0.0.0.0/0
//                   (compute.googleapis.com/compute/v1/projects/<p>/global/firewalls)
//   * CIS-GCP-2.4   Logging sinks export to a destination
//                   (logging.googleapis.com/v2/projects/<p>/sinks)
//
// CredentialRef stores the SA JSON: {"type":"service_account",
// "project_id":"...","private_key_id":"...","private_key":"...",
// "client_email":"..."}
package cloudposture

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GCPCredentials carry the service-account JSON key fields needed for
// the JWT-bearer flow.
type GCPCredentials struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"` // PEM
	ClientEmail  string `json:"client_email"`
}

// GCPCredentialsResolver returns the SA creds for one cloud_account.
type GCPCredentialsResolver func(ctx context.Context, account CloudAccount) (GCPCredentials, error)

// GCPAdapter satisfies ProviderAdapter for GCP projects.
type GCPAdapter struct {
	Resolver   GCPCredentialsResolver
	HTTPClient *http.Client

	mu        sync.Mutex
	tokenByID map[string]cachedToken
}

func NewGCPAdapter(resolver GCPCredentialsResolver) *GCPAdapter {
	return &GCPAdapter{
		Resolver:   resolver,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		tokenByID:  map[string]cachedToken{},
	}
}

func (a *GCPAdapter) Provider() string { return "gcp" }

func (a *GCPAdapter) Scan(ctx context.Context, account CloudAccount) ([]ControlResult, error) {
	creds, err := a.Resolver(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("gcp: resolve credentials: %w", err)
	}
	tok, err := a.token(ctx, creds)
	if err != nil {
		return nil, fmt.Errorf("gcp: acquire token: %w", err)
	}
	var results []ControlResult
	results = append(results, a.checkStorageUBLA(ctx, creds, tok)...)
	results = append(results, a.checkDefaultComputeSA(ctx, creds, tok)...)
	results = append(results, a.checkFirewallSSH(ctx, creds, tok)...)
	results = append(results, a.checkLoggingSinks(ctx, creds, tok))
	return results, nil
}

// ---- controls -------------------------------------------------------------

func (a *GCPAdapter) checkStorageUBLA(ctx context.Context, c GCPCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s&projection=full", c.ProjectID)
	body, err := a.gcpGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-GCP-5.1",
			"Storage bucket: uniform bucket-level access enabled", "storage.bucket", err)}
	}
	type bucket struct {
		Name      string `json:"name"`
		Location  string `json:"location"`
		IamConfig struct {
			UniformBucketLevelAccess struct {
				Enabled bool `json:"enabled"`
			} `json:"uniformBucketLevelAccess"`
		} `json:"iamConfiguration"`
	}
	type listing struct {
		Items []bucket `json:"items"`
	}
	var l listing
	if err := json.Unmarshal(body, &l); err != nil {
		return []ControlResult{manualResult("CIS-GCP-5.1",
			"Storage bucket: uniform bucket-level access enabled", "storage.bucket", err)}
	}
	if len(l.Items) == 0 {
		return []ControlResult{{
			ControlID: "CIS-GCP-5.1", Title: "Storage bucket: uniform bucket-level access enabled",
			Severity: "high", Status: "not_applicable", Evidence: "no buckets in project",
		}}
	}
	var out []ControlResult
	for _, b := range l.Items {
		ctrl := ControlResult{
			ControlID: "CIS-GCP-5.1", Title: "Storage bucket: uniform bucket-level access enabled",
			Severity: "high", Region: b.Location, Resource: "gs://" + b.Name,
			Remediation: "gsutil ubla set on gs://" + b.Name,
		}
		if b.IamConfig.UniformBucketLevelAccess.Enabled {
			ctrl.Status = "pass"
		} else {
			ctrl.Status = "fail"
			ctrl.Evidence = "uniformBucketLevelAccess.enabled=false"
		}
		out = append(out, ctrl)
	}
	return out
}

func (a *GCPAdapter) checkDefaultComputeSA(ctx context.Context, c GCPCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/aggregated/instances", c.ProjectID)
	body, err := a.gcpGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-GCP-1.4",
			"Default Compute Engine service account not used", "compute.instance", err)}
	}
	type sa struct {
		Email string `json:"email"`
	}
	type instance struct {
		Name            string `json:"name"`
		Zone            string `json:"zone"`
		ServiceAccounts []sa   `json:"serviceAccounts"`
	}
	type zoneList struct {
		Instances []instance `json:"instances"`
	}
	type aggregated struct {
		Items map[string]zoneList `json:"items"`
	}
	var a2 aggregated
	if err := json.Unmarshal(body, &a2); err != nil {
		return []ControlResult{manualResult("CIS-GCP-1.4",
			"Default Compute Engine service account not used", "compute.instance", err)}
	}
	defaultSuffix := "-compute@developer.gserviceaccount.com"
	var out []ControlResult
	hadAny := false
	for _, zl := range a2.Items {
		for _, inst := range zl.Instances {
			hadAny = true
			ctrl := ControlResult{
				ControlID: "CIS-GCP-1.4",
				Title:     "Default Compute Engine service account not used",
				Severity:  "medium",
				Region:    shortZone(inst.Zone),
				Resource:  inst.Name,
				Remediation: "Recreate the instance with a custom (least-privileged) SA: " +
					"gcloud compute instances set-service-account " + inst.Name +
					" --service-account=<custom-sa-email>",
			}
			ctrl.Status = "pass"
			for _, s := range inst.ServiceAccounts {
				if strings.HasSuffix(s.Email, defaultSuffix) {
					ctrl.Status = "fail"
					ctrl.Evidence = "uses default SA: " + s.Email
					break
				}
			}
			out = append(out, ctrl)
		}
	}
	if !hadAny {
		return []ControlResult{{
			ControlID: "CIS-GCP-1.4", Title: "Default Compute Engine service account not used",
			Severity: "medium", Status: "not_applicable", Evidence: "no Compute instances in project",
		}}
	}
	return out
}

func (a *GCPAdapter) checkFirewallSSH(ctx context.Context, c GCPCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/global/firewalls", c.ProjectID)
	body, err := a.gcpGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-GCP-3.6",
			"No firewall rule allowing SSH (22) from 0.0.0.0/0", "compute.firewall", err)}
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
	if err := json.Unmarshal(body, &l); err != nil {
		return []ControlResult{manualResult("CIS-GCP-3.6",
			"No firewall rule allowing SSH (22) from 0.0.0.0/0", "compute.firewall", err)}
	}
	var violations []string
	for _, r := range l.Items {
		if r.Disabled || strings.ToUpper(r.Direction) != "INGRESS" {
			continue
		}
		hasAny := false
		for _, s := range r.SourceRanges {
			s = strings.TrimSpace(s)
			if s == "0.0.0.0/0" || s == "::/0" {
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
			if len(alw.Ports) == 0 || alw.IPProtocol == "all" {
				// no port spec → all ports
				violations = append(violations, r.Name+":all")
				continue
			}
			for _, p := range alw.Ports {
				if p == "22" || strings.Contains(p, "20-25") || strings.Contains(p, "0-65535") {
					violations = append(violations, r.Name+":"+p)
					break
				}
				if strings.Contains(p, "-") {
					parts := strings.SplitN(p, "-", 2)
					lo := atoiOrZero(parts[0])
					hi := atoiOrZero(parts[1])
					if 22 >= lo && 22 <= hi {
						violations = append(violations, r.Name+":"+p)
						break
					}
				}
			}
		}
	}
	ctrl := ControlResult{
		ControlID: "CIS-GCP-3.6",
		Title:     "No firewall rule allowing SSH (22) from 0.0.0.0/0",
		Severity:  "high",
		Resource:  "compute.firewall:" + c.ProjectID,
		Remediation: "gcloud compute firewall-rules update <NAME> " +
			"--source-ranges=<corporate-cidr>",
	}
	if len(violations) == 0 {
		ctrl.Status = "pass"
	} else {
		ctrl.Status = "fail"
		ctrl.Evidence = "violating rules: " + strings.Join(violations, ",")
	}
	return []ControlResult{ctrl}
}

func (a *GCPAdapter) checkLoggingSinks(ctx context.Context, c GCPCredentials, tok string) ControlResult {
	url := fmt.Sprintf("https://logging.googleapis.com/v2/projects/%s/sinks", c.ProjectID)
	body, err := a.gcpGET(ctx, url, tok)
	res := ControlResult{
		ControlID: "CIS-GCP-2.4", Title: "Project has at least one logging sink configured",
		Severity:  "medium",
		Resource:  "logging:" + c.ProjectID,
		Remediation: "gcloud logging sinks create <name> storage.googleapis.com/<bucket>",
	}
	if err != nil {
		return manualResultFor(res, err)
	}
	type sink struct {
		Name        string `json:"name"`
		Destination string `json:"destination"`
	}
	type listing struct {
		Sinks []sink `json:"sinks"`
	}
	var l listing
	if err := json.Unmarshal(body, &l); err != nil {
		return manualResultFor(res, err)
	}
	if len(l.Sinks) > 0 {
		res.Status = "pass"
		res.Evidence = fmt.Sprintf("%d sink(s)", len(l.Sinks))
	} else {
		res.Status = "fail"
		res.Evidence = "no logging sinks configured"
	}
	return res
}

// ---- token + HTTP ---------------------------------------------------------

func (a *GCPAdapter) token(ctx context.Context, c GCPCredentials) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := c.ClientEmail + "|" + c.PrivateKeyID
	if t, ok := a.tokenByID[key]; ok && time.Now().Before(t.expires) {
		return t.value, nil
	}
	scopes := strings.Join([]string{
		"https://www.googleapis.com/auth/cloud-platform.read-only",
	}, " ")
	now := time.Now().UTC()
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": c.PrivateKeyID}
	payload := map[string]any{
		"iss":   c.ClientEmail,
		"scope": scopes,
		"aud":   "https://oauth2.googleapis.com/token",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(pb)
	priv, err := parseRSAPrivateKey(c.PrivateKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	jwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	form := url.Values{
		"grant_type": []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  []string{jwt},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("gcp token %d: %s", resp.StatusCode, string(body))
	}
	var r struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", err
	}
	if r.AccessToken == "" {
		return "", errors.New("gcp token: empty access_token in response")
	}
	a.tokenByID[key] = cachedToken{
		value:   r.AccessToken,
		expires: time.Now().Add(time.Duration(r.ExpiresIn-60) * time.Second),
	}
	return r.AccessToken, nil
}

func (a *GCPAdapter) gcpGET(ctx context.Context, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("gcp %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// ---- helpers --------------------------------------------------------------

// parseRSAPrivateKey reads either PKCS1 ("RSA PRIVATE KEY") or PKCS8
// ("PRIVATE KEY") PEM and returns an *rsa.PrivateKey. GCP's SA JSON
// ships PKCS8.
func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("gcp: invalid PEM in private_key")
	}
	if priv, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return priv, nil
	}
	any, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gcp: parse private key: %w", err)
	}
	priv, ok := any.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("gcp: private_key is not RSA (%T)", any)
	}
	return priv, nil
}

// shortZone trims the GCE selfLink prefix down to "us-central1-a".
func shortZone(selfLink string) string {
	if idx := strings.LastIndex(selfLink, "/"); idx >= 0 {
		return selfLink[idx+1:]
	}
	return selfLink
}
