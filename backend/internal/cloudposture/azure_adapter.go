// azure_adapter.go — Azure ProviderAdapter using Azure Resource
// Manager (ARM) REST APIs authenticated via OAuth2 client_credentials
// against Azure AD (login.microsoftonline.com).
//
// Controls implemented:
//   * CIS-Azure-3.1 Storage accounts: secure transfer required (HTTPS only)
//                   — GET /subscriptions/<sub>/providers/Microsoft.Storage/storageAccounts
//   * CIS-Azure-6.1 NSG: SSH (22) restricted from 0.0.0.0/0
//                   — GET /subscriptions/<sub>/providers/Microsoft.Network/networkSecurityGroups
//   * CIS-Azure-8.1 Key Vault: soft-delete enabled
//                   — GET /subscriptions/<sub>/providers/Microsoft.KeyVault/vaults
//   * CIS-Azure-2.7 ASC standard tier enabled
//                   — GET /subscriptions/<sub>/providers/Microsoft.Security/pricings
//
// Authentication path:
//   1. POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
//      grant_type=client_credentials
//      client_id=<app id>
//      client_secret=<app secret>
//      scope=https://management.azure.com/.default
//   2. Cache the token for ~5 min (Azure tokens are 1h).
//   3. GET ARM endpoint with `Authorization: Bearer <token>`.
//
// The CredentialRef in the cloud_accounts row points to a JSON blob
// in the secrets backend: {"tenant_id":"...","client_id":"...",
// "client_secret":"...","subscription_id":"..."}.
package cloudposture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AzureCredentials are the Service Principal secrets used to obtain a
// Bearer token. SubscriptionID identifies which subscription the
// adapter scans.
type AzureCredentials struct {
	TenantID       string
	ClientID       string
	ClientSecret   string
	SubscriptionID string
}

// AzureCredentialsResolver returns the SP creds for one cloud_account.
type AzureCredentialsResolver func(ctx context.Context, account CloudAccount) (AzureCredentials, error)

// AzureAdapter satisfies ProviderAdapter for Azure subscriptions.
type AzureAdapter struct {
	Resolver   AzureCredentialsResolver
	HTTPClient *http.Client

	// Token cache so we don't ask Azure AD on every control check.
	mu        sync.Mutex
	tokenByID map[string]cachedToken
}

type cachedToken struct {
	value   string
	expires time.Time
}

func NewAzureAdapter(resolver AzureCredentialsResolver) *AzureAdapter {
	return &AzureAdapter{
		Resolver:   resolver,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		tokenByID:  map[string]cachedToken{},
	}
}

func (a *AzureAdapter) Provider() string { return "azure" }

func (a *AzureAdapter) Scan(ctx context.Context, account CloudAccount) ([]ControlResult, error) {
	creds, err := a.Resolver(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("azure: resolve credentials: %w", err)
	}
	tok, err := a.token(ctx, creds)
	if err != nil {
		return nil, fmt.Errorf("azure: acquire token: %w", err)
	}
	var results []ControlResult
	results = append(results, a.checkStorageSecureTransfer(ctx, creds, tok)...)
	results = append(results, a.checkNSGOpenSSH(ctx, creds, tok)...)
	results = append(results, a.checkKeyVaultSoftDelete(ctx, creds, tok)...)
	results = append(results, a.checkASCStandardTier(ctx, creds, tok))
	results = append(results, a.extendedScans(ctx, creds, tok)...)
	return results, nil
}

// ---- controls -------------------------------------------------------------

func (a *AzureAdapter) checkStorageSecureTransfer(ctx context.Context, creds AzureCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01", creds.SubscriptionID)
	body, err := a.armGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-Azure-3.1",
			"Storage accounts require HTTPS-only", "azurerm.storageAccounts", err)}
	}
	type props struct {
		SupportsHTTPSTrafficOnly bool `json:"supportsHttpsTrafficOnly"`
	}
	type acct struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Location   string `json:"location"`
		Properties props  `json:"properties"`
	}
	type listing struct {
		Value []acct `json:"value"`
	}
	var l listing
	if err := json.Unmarshal(body, &l); err != nil {
		return []ControlResult{manualResult("CIS-Azure-3.1",
			"Storage accounts require HTTPS-only", "azurerm.storageAccounts", err)}
	}
	if len(l.Value) == 0 {
		return []ControlResult{{
			ControlID: "CIS-Azure-3.1", Title: "Storage accounts require HTTPS-only",
			Severity: "high", Status: "not_applicable",
			Evidence: "no storage accounts in subscription",
		}}
	}
	var out []ControlResult
	for _, ac := range l.Value {
		ctrl := ControlResult{
			ControlID: "CIS-Azure-3.1", Title: "Storage accounts require HTTPS-only",
			Severity: "high", Region: ac.Location, Resource: ac.ID,
			Remediation: "az storage account update --name " + ac.Name + " --https-only true",
		}
		if ac.Properties.SupportsHTTPSTrafficOnly {
			ctrl.Status = "pass"
		} else {
			ctrl.Status = "fail"
			ctrl.Evidence = "supportsHttpsTrafficOnly=false"
		}
		out = append(out, ctrl)
	}
	return out
}

func (a *AzureAdapter) checkNSGOpenSSH(ctx context.Context, creds AzureCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01", creds.SubscriptionID)
	body, err := a.armGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-Azure-6.1",
			"NSG: SSH (22) restricted from 0.0.0.0/0", "azurerm.nsg", err)}
	}
	type rule struct {
		Name       string `json:"name"`
		Properties struct {
			Direction              string   `json:"direction"`
			Access                 string   `json:"access"`
			Protocol               string   `json:"protocol"`
			DestinationPortRange   string   `json:"destinationPortRange"`
			DestinationPortRanges  []string `json:"destinationPortRanges"`
			SourceAddressPrefix    string   `json:"sourceAddressPrefix"`
			SourceAddressPrefixes  []string `json:"sourceAddressPrefixes"`
		} `json:"properties"`
	}
	type nsg struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Location   string `json:"location"`
		Properties struct {
			SecurityRules []rule `json:"securityRules"`
		} `json:"properties"`
	}
	type listing struct {
		Value []nsg `json:"value"`
	}
	var l listing
	if err := json.Unmarshal(body, &l); err != nil {
		return []ControlResult{manualResult("CIS-Azure-6.1",
			"NSG: SSH (22) restricted from 0.0.0.0/0", "azurerm.nsg", err)}
	}
	if len(l.Value) == 0 {
		return []ControlResult{{
			ControlID: "CIS-Azure-6.1", Title: "NSG: SSH (22) restricted from 0.0.0.0/0",
			Severity: "high", Status: "not_applicable",
			Evidence: "no NSGs in subscription",
		}}
	}
	var out []ControlResult
	for _, ng := range l.Value {
		violation := ""
		for _, r := range ng.Properties.SecurityRules {
			if r.Properties.Direction != "Inbound" || r.Properties.Access != "Allow" {
				continue
			}
			if !portRangeIncludes(r.Properties.DestinationPortRange, r.Properties.DestinationPortRanges, 22) {
				continue
			}
			sources := append([]string{}, r.Properties.SourceAddressPrefixes...)
			if r.Properties.SourceAddressPrefix != "" {
				sources = append(sources, r.Properties.SourceAddressPrefix)
			}
			for _, s := range sources {
				if isInternetCIDR(s) {
					violation = fmt.Sprintf("rule %s allows 22 from %s", r.Name, s)
					break
				}
			}
			if violation != "" {
				break
			}
		}
		ctrl := ControlResult{
			ControlID: "CIS-Azure-6.1", Title: "NSG: SSH (22) restricted from 0.0.0.0/0",
			Severity: "high", Region: ng.Location, Resource: ng.ID,
			Remediation: "Restrict the source range or remove the rule.",
		}
		if violation == "" {
			ctrl.Status = "pass"
		} else {
			ctrl.Status = "fail"
			ctrl.Evidence = violation
		}
		out = append(out, ctrl)
	}
	return out
}

func (a *AzureAdapter) checkKeyVaultSoftDelete(ctx context.Context, creds AzureCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resources?$filter=resourceType%%20eq%%20%%27Microsoft.KeyVault/vaults%%27&api-version=2021-04-01&%%24expand=properties",
		creds.SubscriptionID)
	body, err := a.armGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-Azure-8.1",
			"Key Vault: soft-delete enabled", "azurerm.keyvault", err)}
	}
	type vault struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Location   string `json:"location"`
		Properties struct {
			EnableSoftDelete *bool `json:"enableSoftDelete"`
		} `json:"properties"`
	}
	type listing struct {
		Value []vault `json:"value"`
	}
	var l listing
	if err := json.Unmarshal(body, &l); err != nil {
		return []ControlResult{manualResult("CIS-Azure-8.1",
			"Key Vault: soft-delete enabled", "azurerm.keyvault", err)}
	}
	if len(l.Value) == 0 {
		return []ControlResult{{
			ControlID: "CIS-Azure-8.1", Title: "Key Vault: soft-delete enabled",
			Severity: "high", Status: "not_applicable",
			Evidence: "no Key Vaults in subscription",
		}}
	}
	var out []ControlResult
	for _, v := range l.Value {
		ctrl := ControlResult{
			ControlID: "CIS-Azure-8.1", Title: "Key Vault: soft-delete enabled",
			Severity: "high", Region: v.Location, Resource: v.ID,
			Remediation: "az keyvault update --name " + v.Name + " --enable-soft-delete true",
		}
		// As of Azure 2020-04-01-preview, soft-delete cannot be disabled.
		// API returns nil → assume enabled. False explicit → fail.
		switch {
		case v.Properties.EnableSoftDelete == nil:
			ctrl.Status = "pass"
			ctrl.Evidence = "soft-delete property not present (default-on for vaults created post-2020)"
		case *v.Properties.EnableSoftDelete:
			ctrl.Status = "pass"
		default:
			ctrl.Status = "fail"
			ctrl.Evidence = "enableSoftDelete=false"
		}
		out = append(out, ctrl)
	}
	return out
}

func (a *AzureAdapter) checkASCStandardTier(ctx context.Context, creds AzureCredentials, tok string) ControlResult {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/pricings?api-version=2024-01-01", creds.SubscriptionID)
	body, err := a.armGET(ctx, url, tok)
	res := ControlResult{
		ControlID: "CIS-Azure-2.7", Title: "Microsoft Defender for Cloud: standard tier on key plans",
		Severity: "medium", Resource: fmt.Sprintf("/subscriptions/%s", creds.SubscriptionID),
		Remediation: "az security pricing create --name VirtualMachines --tier Standard",
	}
	if err != nil {
		return manualResultFor(res, err)
	}
	type pricing struct {
		Name       string `json:"name"`
		Properties struct {
			PricingTier string `json:"pricingTier"`
		} `json:"properties"`
	}
	type listing struct {
		Value []pricing `json:"value"`
	}
	var l listing
	if err := json.Unmarshal(body, &l); err != nil {
		return manualResultFor(res, err)
	}
	required := map[string]bool{
		"VirtualMachines": false, "AppServices": false,
		"SqlServers": false, "StorageAccounts": false, "KeyVaults": false,
	}
	for _, p := range l.Value {
		if _, want := required[p.Name]; want {
			required[p.Name] = (p.Properties.PricingTier == "Standard")
		}
	}
	missing := []string{}
	for k, ok := range required {
		if !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) == 0 {
		res.Status = "pass"
	} else {
		res.Status = "fail"
		res.Evidence = "non-standard tier on: " + strings.Join(missing, ",")
	}
	return res
}

// ---- HTTP + token ---------------------------------------------------------

func (a *AzureAdapter) token(ctx context.Context, c AzureCredentials) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := c.TenantID + "|" + c.ClientID
	if t, ok := a.tokenByID[key]; ok && time.Now().Before(t.expires) {
		return t.value, nil
	}
	form := url.Values{
		"client_id":     []string{c.ClientID},
		"client_secret": []string{c.ClientSecret},
		"grant_type":    []string{"client_credentials"},
		"scope":         []string{"https://management.azure.com/.default"},
	}
	endpoint := "https://login.microsoftonline.com/" + c.TenantID + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
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
		return "", fmt.Errorf("azure token %d: %s", resp.StatusCode, string(body))
	}
	var r struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", err
	}
	if r.AccessToken == "" {
		return "", fmt.Errorf("azure token: empty access_token in response")
	}
	a.tokenByID[key] = cachedToken{
		value:   r.AccessToken,
		expires: time.Now().Add(time.Duration(r.ExpiresIn-60) * time.Second),
	}
	return r.AccessToken, nil
}

func (a *AzureAdapter) armGET(ctx context.Context, url, token string) ([]byte, error) {
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
		return nil, fmt.Errorf("azure %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// ---- helpers --------------------------------------------------------------

// portRangeIncludes returns true if 'port' falls within either the
// single range or any of the listed ranges. Azure NSG rules can use
// "*", "22", "20-100", or list form.
func portRangeIncludes(single string, list []string, port int) bool {
	test := func(s string) bool {
		s = strings.TrimSpace(s)
		if s == "*" {
			return true
		}
		if strings.Contains(s, "-") {
			parts := strings.SplitN(s, "-", 2)
			if len(parts) != 2 {
				return false
			}
			lo := atoiOrZero(parts[0])
			hi := atoiOrZero(parts[1])
			return port >= lo && port <= hi
		}
		return atoiOrZero(s) == port
	}
	if test(single) {
		return true
	}
	for _, p := range list {
		if test(p) {
			return true
		}
	}
	return false
}

func atoiOrZero(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// isInternetCIDR captures the patterns Azure uses to denote any-source.
// "Internet" is a built-in service tag.
func isInternetCIDR(s string) bool {
	s = strings.TrimSpace(s)
	switch s {
	case "*", "0.0.0.0/0", "::/0", "Internet":
		return true
	}
	return false
}
