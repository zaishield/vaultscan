// aws_adapter.go — AWS-side ProviderAdapter implementing a curated
// subset of the CIS AWS Foundations Benchmark. Each control issues
// real, SigV4-signed REST calls against the AWS APIs, then maps the
// response onto a canonical ControlResult.
//
// Controls implemented:
//   * CIS-AWS-1.4   No root account access keys (IAM:GetAccountSummary)
//   * CIS-AWS-1.5   MFA on root account (IAM:GetAccountSummary)
//   * CIS-AWS-1.8   Password policy: min length ≥ 14
//                                          (IAM:GetAccountPasswordPolicy)
//   * CIS-AWS-2.1.5 S3 bucket public access block
//                                          (S3:ListBuckets + GetPublicAccessBlock)
//   * CIS-AWS-3.1   CloudTrail enabled in all regions
//                                          (CloudTrail:DescribeTrails)
//   * CIS-AWS-2.2   Default EBS encryption  (EC2:GetEbsEncryptionByDefault)
//
// Authentication: long-lived access key + secret stored via the
// secrets backend (CredentialRef). For STS-assumed roles, the caller
// supplies a SessionToken alongside; AWSCredentialsResolver decides
// which path to use. RoleARN is reserved for AssumeRole exchanges
// (not implemented here — covered by the dev ops handbook).
//
// Error policy: a control that fails to evaluate (network, credential,
// permission) is returned as Status="manual" with the underlying
// AWS error captured in Evidence — the operator can decide whether
// to fix the control or fix the credential.
package cloudposture

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/httputil"
)

// AWSCredentialsResolver returns the credentials for a given account.
// The default implementation looks up the CredentialRef in the secrets
// backend; tests inject a static resolver.
type AWSCredentialsResolver func(ctx context.Context, account CloudAccount) (AWSCredentials, error)

// AWSAdapter is the production AWS ProviderAdapter. New("us-east-1", ...)
// creates one bound to a specific home region (used for global IAM
// calls); per-region S3/EC2 calls use the account's Regions list.
type AWSAdapter struct {
	HomeRegion  string
	Resolver    AWSCredentialsResolver
	HTTPClient  *http.Client
}

// NewAWSAdapter constructs an adapter using the central httputil
// client (timeouts, pool reuse, air-gap allowlist), with a
// CheckRedirect that refuses redirects entirely — AWS service
// endpoints don't redirect, so any 3xx from this surface is either
// a misconfig or a hijack attempt.
func NewAWSAdapter(homeRegion string, resolver AWSCredentialsResolver) *AWSAdapter {
	c := httputil.NewClient(httputil.Options{Timeout: 30 * time.Second})
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &AWSAdapter{
		HomeRegion: homeRegion,
		Resolver:   resolver,
		HTTPClient: c,
	}
}

func (a *AWSAdapter) Provider() string { return "aws" }

// Scan runs every CIS control we implement and returns the consolidated
// list. Failures inside one control don't abort the others — each
// becomes its own ControlResult with Status=manual + Evidence=err.
func (a *AWSAdapter) Scan(ctx context.Context, account CloudAccount) ([]ControlResult, error) {
	creds, err := a.Resolver(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("aws: resolve credentials: %w", err)
	}
	var results []ControlResult
	results = append(results, a.checkAccountSummary(ctx, account, creds)...)
	results = append(results, a.checkPasswordPolicy(ctx, account, creds))
	results = append(results, a.checkS3PublicAccessBlock(ctx, account, creds)...)
	results = append(results, a.checkCloudTrail(ctx, account, creds, account.Regions)...)
	results = append(results, a.checkEBSEncryptionByDefault(ctx, account, creds, account.Regions)...)
	results = append(results, a.extendedScans(ctx, account, creds)...)
	return results, nil
}

// checkAccountSummary runs IAM GetAccountSummary which returns a map
// covering both CIS-1.4 (root keys) and CIS-1.5 (root MFA).
func (a *AWSAdapter) checkAccountSummary(ctx context.Context, _ CloudAccount, creds AWSCredentials) []ControlResult {
	body, err := a.iamCall(ctx, creds, "GetAccountSummary")
	if err != nil {
		return []ControlResult{
			manualResult("CIS-AWS-1.4", "No root account access keys", "iam", err),
			manualResult("CIS-AWS-1.5", "MFA on root account", "iam", err),
		}
	}
	type entry struct {
		Key   string `xml:"key"`
		Value int    `xml:"value"`
	}
	type resp struct {
		Result struct {
			Map struct {
				Entries []entry `xml:"entry"`
			} `xml:"SummaryMap"`
		} `xml:"GetAccountSummaryResult"`
	}
	var r resp
	if err := xml.Unmarshal(body, &r); err != nil {
		return []ControlResult{
			manualResult("CIS-AWS-1.4", "No root account access keys", "iam", err),
			manualResult("CIS-AWS-1.5", "MFA on root account", "iam", err),
		}
	}
	flat := map[string]int{}
	for _, e := range r.Result.Map.Entries {
		flat[e.Key] = e.Value
	}
	rootKeys := flat["AccountAccessKeysPresent"]
	rootMFA := flat["AccountMFAEnabled"]
	rootKeysCtrl := ControlResult{
		ControlID:   "CIS-AWS-1.4",
		Title:       "No root account access keys",
		Severity:    "critical",
		Region:      a.HomeRegion,
		Resource:    "iam:::root",
		Remediation: "Delete root access keys via IAM console.",
		Status:      "pass",
	}
	if rootKeys > 0 {
		rootKeysCtrl.Status = "fail"
		rootKeysCtrl.Evidence = fmt.Sprintf("AccountAccessKeysPresent=%d", rootKeys)
	}
	rootMFACtrl := ControlResult{
		ControlID:   "CIS-AWS-1.5",
		Title:       "MFA on root account",
		Severity:    "critical",
		Region:      a.HomeRegion,
		Resource:    "iam:::root",
		Remediation: "Enable MFA on root in IAM console > Security credentials.",
		Status:      "pass",
	}
	if rootMFA != 1 {
		rootMFACtrl.Status = "fail"
		rootMFACtrl.Evidence = "AccountMFAEnabled=0"
	}
	return []ControlResult{rootKeysCtrl, rootMFACtrl}
}

// checkPasswordPolicy enforces CIS-AWS-1.8 (min length ≥ 14).
func (a *AWSAdapter) checkPasswordPolicy(ctx context.Context, _ CloudAccount, creds AWSCredentials) ControlResult {
	body, err := a.iamCall(ctx, creds, "GetAccountPasswordPolicy")
	res := ControlResult{
		ControlID: "CIS-AWS-1.8", Title: "IAM password policy minimum length ≥ 14",
		Severity: "high", Region: a.HomeRegion, Resource: "iam::password-policy",
		Remediation: "aws iam update-account-password-policy --minimum-password-length 14",
	}
	if err != nil {
		// NoSuchEntity = no policy at all → fail.
		if strings.Contains(err.Error(), "NoSuchEntity") {
			res.Status = "fail"
			res.Evidence = "no password policy configured"
			return res
		}
		return manualResultFor(res, err)
	}
	type policy struct {
		Result struct {
			Policy struct {
				MinimumPasswordLength int `xml:"MinimumPasswordLength"`
			} `xml:"PasswordPolicy"`
		} `xml:"GetAccountPasswordPolicyResult"`
	}
	var p policy
	if err := xml.Unmarshal(body, &p); err != nil {
		return manualResultFor(res, err)
	}
	if p.Result.Policy.MinimumPasswordLength >= 14 {
		res.Status = "pass"
	} else {
		res.Status = "fail"
		res.Evidence = fmt.Sprintf("MinimumPasswordLength=%d", p.Result.Policy.MinimumPasswordLength)
	}
	return res
}

// checkS3PublicAccessBlock walks every bucket and verifies a public
// access block is in place.
func (a *AWSAdapter) checkS3PublicAccessBlock(ctx context.Context, _ CloudAccount, creds AWSCredentials) []ControlResult {
	body, err := a.s3Call(ctx, creds, http.MethodGet, "https://s3.amazonaws.com/", a.HomeRegion)
	if err != nil {
		return []ControlResult{
			manualResult("CIS-AWS-2.1.5", "S3 bucket public access block enforced", "s3", err),
		}
	}
	type bucket struct {
		Name string `xml:"Name"`
	}
	type listAll struct {
		Buckets struct {
			Bucket []bucket `xml:"Bucket"`
		} `xml:"Buckets"`
	}
	var l listAll
	if err := xml.Unmarshal(body, &l); err != nil {
		return []ControlResult{manualResult("CIS-AWS-2.1.5", "S3 bucket public access block enforced", "s3", err)}
	}
	if len(l.Buckets.Bucket) == 0 {
		return []ControlResult{{
			ControlID: "CIS-AWS-2.1.5", Title: "S3 bucket public access block enforced",
			Severity: "high", Status: "not_applicable", Resource: "s3:::*",
			Evidence: "no buckets in account",
		}}
	}
	var out []ControlResult
	for _, b := range l.Buckets.Bucket {
		ctrl := ControlResult{
			ControlID: "CIS-AWS-2.1.5",
			Title:     "S3 bucket public access block enforced",
			Severity:  "high", Resource: "s3:::" + b.Name,
			Remediation: "aws s3api put-public-access-block --bucket " + b.Name +
				" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
		}
		_, err := a.s3Call(ctx, creds, http.MethodGet,
			"https://"+b.Name+".s3.amazonaws.com/?publicAccessBlock", a.HomeRegion)
		if err != nil {
			if strings.Contains(err.Error(), "NoSuchPublicAccessBlockConfiguration") {
				ctrl.Status = "fail"
				ctrl.Evidence = "no public access block configured"
			} else {
				ctrl.Status = "manual"
				ctrl.Evidence = err.Error()
			}
		} else {
			ctrl.Status = "pass"
		}
		out = append(out, ctrl)
	}
	return out
}

// checkCloudTrail confirms at least one multi-region trail is enabled
// (CIS-AWS-3.1). Iterates regions to pick up trails in any home region.
func (a *AWSAdapter) checkCloudTrail(ctx context.Context, _ CloudAccount, creds AWSCredentials, regions []string) []ControlResult {
	if len(regions) == 0 {
		regions = []string{a.HomeRegion}
	}
	res := ControlResult{
		ControlID: "CIS-AWS-3.1", Title: "CloudTrail enabled and multi-region",
		Severity: "high", Resource: "cloudtrail:::*",
		Remediation: "Create a multi-region trail: aws cloudtrail create-trail --name org-trail --is-multi-region-trail",
	}
	type trail struct {
		Name             string `json:"Name"`
		IsMultiRegion    bool   `json:"IsMultiRegionTrail"`
		HomeRegion       string `json:"HomeRegion"`
	}
	type resp struct {
		TrailList []trail `json:"trailList"`
	}
	for _, r := range regions {
		host := fmt.Sprintf("cloudtrail.%s.amazonaws.com", r)
		body, err := a.jsonAPICall(ctx, creds, "POST",
			"https://"+host+"/", r, "cloudtrail",
			"CloudTrail_20131101.DescribeTrails", []byte("{}"))
		if err != nil {
			continue
		}
		var rr resp
		if err := json.Unmarshal(body, &rr); err != nil {
			continue
		}
		for _, t := range rr.TrailList {
			if t.IsMultiRegion {
				res.Status = "pass"
				res.Region = t.HomeRegion
				res.Evidence = fmt.Sprintf("trail=%s home=%s", t.Name, t.HomeRegion)
				return []ControlResult{res}
			}
		}
	}
	res.Status = "fail"
	res.Evidence = "no multi-region trail found in any of: " + strings.Join(regions, ",")
	return []ControlResult{res}
}

// checkEBSEncryptionByDefault iterates per-region EC2 endpoints and
// confirms the default-encryption flag is set in each region the
// tenant operates in.
func (a *AWSAdapter) checkEBSEncryptionByDefault(ctx context.Context, _ CloudAccount, creds AWSCredentials, regions []string) []ControlResult {
	if len(regions) == 0 {
		regions = []string{a.HomeRegion}
	}
	// Bounded parallelism — a 30-region scan against the AWS EC2
	// endpoint serially can take minutes per Scan() call. Limit
	// concurrency to 8 so we don't blow the EC2 rate limit either.
	type result struct {
		idx int
		ctrl ControlResult
	}
	results := make([]ControlResult, len(regions))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, r := range regions {
		wg.Add(1)
		go func(i int, r string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctrl := ControlResult{
				ControlID: "CIS-AWS-2.2", Title: "EBS default encryption enabled",
				Severity: "high", Resource: "ec2:::ebs-default-encryption", Region: r,
				Remediation: "aws ec2 enable-ebs-encryption-by-default --region " + r,
			}
			body, err := a.ec2Call(ctx, creds, r, "GetEbsEncryptionByDefault", "2016-11-15")
			if err != nil {
				results[i] = manualResultFor(ctrl, err)
				return
			}
			type ec2resp struct {
				XMLName               xml.Name `xml:"GetEbsEncryptionByDefaultResponse"`
				EbsEncryptionByDefault bool    `xml:"ebsEncryptionByDefault"`
			}
			var rr ec2resp
			if err := xml.Unmarshal(body, &rr); err != nil {
				results[i] = manualResultFor(ctrl, err)
				return
			}
			if rr.EbsEncryptionByDefault {
				ctrl.Status = "pass"
			} else {
				ctrl.Status = "fail"
				ctrl.Evidence = "ebsEncryptionByDefault=false"
			}
			results[i] = ctrl
		}(i, r)
	}
	wg.Wait()
	return results
}

// ---- low-level HTTP wrappers ---------------------------------------------

// iamCall issues a global IAM query-protocol call.
func (a *AWSAdapter) iamCall(ctx context.Context, creds AWSCredentials, action string) ([]byte, error) {
	return a.iamCallRaw(ctx, creds, strings.NewReader("Action="+action+"&Version=2010-05-08"))
}

// iamCallRaw is the underlying helper that takes an arbitrary form
// reader (used by iamCallWithParam in the extended controls file).
func (a *AWSAdapter) iamCallRaw(ctx context.Context, creds AWSCredentials, form *strings.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://iam.amazonaws.com/", form)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if err := signRequestSigV4(req, "us-east-1", "iam", creds); err != nil {
		return nil, err
	}
	return a.do(req)
}

// s3Call issues an S3 REST call. URL is fully-qualified; region used
// for SigV4 derivation only.
func (a *AWSAdapter) s3Call(ctx context.Context, creds AWSCredentials, method, url, region string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	if err := signRequestSigV4(req, region, "s3", creds); err != nil {
		return nil, err
	}
	return a.do(req)
}

// ec2Call issues a per-region EC2 query-protocol call.
func (a *AWSAdapter) ec2Call(ctx context.Context, creds AWSCredentials, region, action, version string) ([]byte, error) {
	form := strings.NewReader("Action=" + action + "&Version=" + version)
	host := fmt.Sprintf("ec2.%s.amazonaws.com", region)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/", form)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if err := signRequestSigV4(req, region, "ec2", creds); err != nil {
		return nil, err
	}
	return a.do(req)
}

// jsonAPICall handles the JSON-protocol AWS APIs (CloudTrail, etc.)
// where the action goes in X-Amz-Target.
func (a *AWSAdapter) jsonAPICall(ctx context.Context, creds AWSCredentials,
	method, url, region, service, target string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	if err := signRequestSigV4(req, region, service, creds); err != nil {
		return nil, err
	}
	return a.do(req)
}

func (a *AWSAdapter) do(req *http.Request) ([]byte, error) {
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
		// AWS error responses may be XML or JSON depending on protocol.
		// Pass the body through verbatim — caller can grep for known
		// error codes (NoSuchEntity, NoSuchPublicAccessBlockConfiguration).
		return nil, fmt.Errorf("aws %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// ---- helpers --------------------------------------------------------------

func manualResult(id, title, resource string, err error) ControlResult {
	return ControlResult{
		ControlID: id, Title: title, Severity: "high",
		Resource: resource, Status: "manual",
		Evidence: err.Error(),
	}
}

// manualResultFor preserves the partial-filled ControlResult and just
// flips status to manual + attaches the err message.
func manualResultFor(r ControlResult, err error) ControlResult {
	r.Status = "manual"
	r.Evidence = err.Error()
	return r
}
