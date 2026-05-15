// azure_controls_extended.go — additional CIS-Azure controls beyond
// the initial 4 in azure_adapter.go.
package cloudposture

import (
	"context"
	"encoding/json"
	"fmt"
)

func (a *AzureAdapter) extendedScans(ctx context.Context, c AzureCredentials, tok string) []ControlResult {
	var out []ControlResult
	// IAM / Identity
	out = append(out, a.checkAzureMFAOnAdmins(ctx))
	out = append(out, a.checkConditionalAccessForRiskyLogin(ctx))
	out = append(out, a.checkPIMEnabled(ctx))
	out = append(out, a.checkBuiltInGuestRestricted(ctx))
	// Compute
	out = append(out, a.checkVMOSDiskEncrypted(ctx, c, tok)...)
	out = append(out, a.checkVMUnattachedDisksEncrypted(ctx))
	out = append(out, a.checkVMScaleSetAutoUpgrade(ctx))
	// Storage
	out = append(out, a.checkStoragePublicAccessDisabled(ctx, c, tok)...)
	out = append(out, a.checkStorageBlobLogging(ctx))
	out = append(out, a.checkStorageMinimumTLS12(ctx, c, tok)...)
	out = append(out, a.checkStorageAllowFromTrustedServices(ctx))
	// Network
	out = append(out, a.checkNSGOpenRDP(ctx, c, tok)...)
	out = append(out, a.checkNetworkWatcherEnabled(ctx))
	out = append(out, a.checkAppGatewayWAFEnabled(ctx))
	// Database
	out = append(out, a.checkSQLAuditingEnabled(ctx))
	out = append(out, a.checkSQLTransparentDataEncryption(ctx))
	out = append(out, a.checkPostgreSQLLogConnections(ctx))
	out = append(out, a.checkSQLAdvancedDataSecurity(ctx))
	// Key Vault
	out = append(out, a.checkKeyVaultPurgeProtection(ctx, c, tok)...)
	out = append(out, a.checkKeyVaultRBAC(ctx))
	// Logging / Defender
	out = append(out, a.checkActivityLogRetention(ctx))
	out = append(out, a.checkDiagnosticSettings(ctx))
	out = append(out, a.checkDefenderForServers(ctx))
	out = append(out, a.checkDefenderForKeyVault(ctx))
	out = append(out, a.checkDefenderForAppService(ctx))
	out = append(out, a.checkDefenderForContainerRegistry(ctx))
	// AppService
	out = append(out, a.checkAppServiceHTTPSOnly(ctx))
	out = append(out, a.checkAppServiceManagedIdentity(ctx))
	out = append(out, a.checkAppServiceMinTLS(ctx))
	return out
}

// ----- IAM ----------------------------------------------------------------

func (a *AzureAdapter) checkAzureMFAOnAdmins(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-1.1.1", "MFA enabled for all Azure AD admins",
		"Enable Conditional Access policy: require MFA for directory roles.")
}

func (a *AzureAdapter) checkConditionalAccessForRiskyLogin(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-1.2.2", "Conditional Access: block risky sign-ins",
		"Configure Identity Protection user/sign-in risk policies.")
}

func (a *AzureAdapter) checkPIMEnabled(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-1.21", "Privileged Identity Management active",
		"Enable PIM and require it for Owner/Contributor role activations.")
}

func (a *AzureAdapter) checkBuiltInGuestRestricted(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-1.5", "Guest user invitations restricted",
		"Set guest invite restrictions in Azure AD external collaboration settings.")
}

// ----- Compute / VM -------------------------------------------------------

func (a *AzureAdapter) checkVMOSDiskEncrypted(ctx context.Context, c AzureCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01", c.SubscriptionID)
	body, err := a.armGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-Azure-7.2",
			"VM OS disks encrypted (ADE/SSE)", "azurerm.vm.os-disk", err)}
	}
	type vm struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Properties struct {
			StorageProfile struct {
				OSDisk struct {
					EncryptionSettings struct {
						Enabled bool `json:"enabled"`
					} `json:"encryptionSettings"`
				} `json:"osDisk"`
			} `json:"storageProfile"`
		} `json:"properties"`
	}
	type listing struct {
		Value []vm `json:"value"`
	}
	var l listing
	if err := json.Unmarshal(body, &l); err != nil {
		return []ControlResult{manualResult("CIS-Azure-7.2",
			"VM OS disks encrypted (ADE/SSE)", "azurerm.vm.os-disk", err)}
	}
	if len(l.Value) == 0 {
		return []ControlResult{{
			ControlID: "CIS-Azure-7.2", Title: "VM OS disks encrypted (ADE/SSE)",
			Severity: "high", Status: "not_applicable",
			Evidence: "no VMs in subscription",
		}}
	}
	var out []ControlResult
	for _, v := range l.Value {
		ctrl := ControlResult{
			ControlID: "CIS-Azure-7.2", Title: "VM OS disks encrypted (ADE/SSE)",
			Severity: "high", Resource: v.ID,
			Remediation: "Enable encryption: az vm encryption enable --name " + v.Name + " --resource-group <rg>",
		}
		// Note: SSE (storage-side) is on by default for managed disks
		// since 2017; ADE (in-OS) requires explicit enable. We mark
		// as pass when EncryptionSettings.Enabled OR no settings (SSE default).
		if v.Properties.StorageProfile.OSDisk.EncryptionSettings.Enabled {
			ctrl.Status = "pass"
		} else {
			ctrl.Status = "manual"
			ctrl.Evidence = "no ADE settings; SSE defaults on for managed disks but verify"
		}
		out = append(out, ctrl)
	}
	return out
}

func (a *AzureAdapter) checkVMUnattachedDisksEncrypted(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-7.3", "Unattached managed disks encrypted",
		"Iterate managed disks; verify encryptionSettingsCollection.enabled = true.")
}

func (a *AzureAdapter) checkVMScaleSetAutoUpgrade(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-7.6", "VM scale sets: automatic OS upgrades",
		"Set upgradePolicy.mode = 'Automatic' on scale sets.")
}

// ----- Storage ------------------------------------------------------------

func (a *AzureAdapter) checkStoragePublicAccessDisabled(ctx context.Context, c AzureCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01", c.SubscriptionID)
	body, err := a.armGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-Azure-3.5",
			"Storage accounts: public network access disabled", "azurerm.storageAccounts", err)}
	}
	type acct struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Location   string `json:"location"`
		Properties struct {
			PublicNetworkAccess string `json:"publicNetworkAccess"`
		} `json:"properties"`
	}
	type listing struct {
		Value []acct `json:"value"`
	}
	var l listing
	_ = json.Unmarshal(body, &l)
	var out []ControlResult
	for _, ac := range l.Value {
		ctrl := ControlResult{
			ControlID: "CIS-Azure-3.5", Title: "Storage accounts: public network access disabled",
			Severity: "high", Region: ac.Location, Resource: ac.ID,
			Remediation: "az storage account update --name " + ac.Name + " --public-network-access Disabled",
		}
		if ac.Properties.PublicNetworkAccess == "Disabled" {
			ctrl.Status = "pass"
		} else {
			ctrl.Status = "fail"
			ctrl.Evidence = "publicNetworkAccess=" + ac.Properties.PublicNetworkAccess
		}
		out = append(out, ctrl)
	}
	return out
}

func (a *AzureAdapter) checkStorageBlobLogging(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-5.1.3", "Storage blob diagnostic logs enabled",
		"Configure diagnostic settings: enable blob StorageRead/Write/Delete logs.")
}

func (a *AzureAdapter) checkStorageMinimumTLS12(ctx context.Context, c AzureCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01", c.SubscriptionID)
	body, err := a.armGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-Azure-3.15",
			"Storage minimum TLS = 1.2", "azurerm.storageAccounts", err)}
	}
	type acct struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Location   string `json:"location"`
		Properties struct {
			MinimumTLSVersion string `json:"minimumTlsVersion"`
		} `json:"properties"`
	}
	type listing struct {
		Value []acct `json:"value"`
	}
	var l listing
	_ = json.Unmarshal(body, &l)
	var out []ControlResult
	for _, ac := range l.Value {
		ctrl := ControlResult{
			ControlID: "CIS-Azure-3.15", Title: "Storage minimum TLS = 1.2",
			Severity: "medium", Region: ac.Location, Resource: ac.ID,
			Remediation: "az storage account update --name " + ac.Name + " --min-tls-version TLS1_2",
		}
		if ac.Properties.MinimumTLSVersion == "TLS1_2" || ac.Properties.MinimumTLSVersion == "TLS1_3" {
			ctrl.Status = "pass"
		} else {
			ctrl.Status = "fail"
			ctrl.Evidence = "minimumTlsVersion=" + ac.Properties.MinimumTLSVersion
		}
		out = append(out, ctrl)
	}
	return out
}

func (a *AzureAdapter) checkStorageAllowFromTrustedServices(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-3.7", "Storage: 'Allow trusted Azure services' enabled",
		"Set networkAcls.bypass = 'AzureServices' on every storage account.")
}

// ----- Network ------------------------------------------------------------

func (a *AzureAdapter) checkNSGOpenRDP(ctx context.Context, c AzureCredentials, tok string) []ControlResult {
	// Same pattern as checkNSGOpenSSH from the main file but for port 3389.
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01", c.SubscriptionID)
	body, err := a.armGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-Azure-6.2",
			"NSG: RDP (3389) restricted from 0.0.0.0/0", "azurerm.nsg", err)}
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
	_ = json.Unmarshal(body, &l)
	var out []ControlResult
	for _, ng := range l.Value {
		violation := ""
		for _, r := range ng.Properties.SecurityRules {
			if r.Properties.Direction != "Inbound" || r.Properties.Access != "Allow" {
				continue
			}
			if !portRangeIncludes(r.Properties.DestinationPortRange,
				r.Properties.DestinationPortRanges, 3389) {
				continue
			}
			sources := append([]string{}, r.Properties.SourceAddressPrefixes...)
			if r.Properties.SourceAddressPrefix != "" {
				sources = append(sources, r.Properties.SourceAddressPrefix)
			}
			for _, s := range sources {
				if isInternetCIDR(s) {
					violation = fmt.Sprintf("rule %s allows 3389 from %s", r.Name, s)
					break
				}
			}
			if violation != "" {
				break
			}
		}
		ctrl := ControlResult{
			ControlID: "CIS-Azure-6.2", Title: "NSG: RDP (3389) restricted from 0.0.0.0/0",
			Severity: "high", Region: ng.Location, Resource: ng.ID,
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

func (a *AzureAdapter) checkNetworkWatcherEnabled(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-6.4", "Network Watcher enabled in every region with VMs",
		"az network watcher configure --enabled true --locations <region>")
}

func (a *AzureAdapter) checkAppGatewayWAFEnabled(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-9.10", "Application Gateway uses WAF SKU",
		"Recreate Application Gateway with WAF_v2 SKU.")
}

// ----- DB / SQL -----------------------------------------------------------

func (a *AzureAdapter) checkSQLAuditingEnabled(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-4.1.1", "SQL Server: auditing enabled",
		"az sql server audit-policy update --state Enabled")
}

func (a *AzureAdapter) checkSQLTransparentDataEncryption(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-4.1.3", "SQL Database: TDE enabled",
		"az sql db tde set --status Enabled")
}

func (a *AzureAdapter) checkPostgreSQLLogConnections(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-4.3.2", "PostgreSQL: log_connections=on",
		"az postgres server configuration set --name log_connections --value on")
}

func (a *AzureAdapter) checkSQLAdvancedDataSecurity(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-4.2.1", "SQL Advanced Threat Protection enabled",
		"az sql server threat-policy update --state Enabled")
}

// ----- Key Vault ----------------------------------------------------------

func (a *AzureAdapter) checkKeyVaultPurgeProtection(ctx context.Context, c AzureCredentials, tok string) []ControlResult {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resources?$filter=resourceType%%20eq%%20%%27Microsoft.KeyVault/vaults%%27&api-version=2021-04-01&%%24expand=properties",
		c.SubscriptionID)
	body, err := a.armGET(ctx, url, tok)
	if err != nil {
		return []ControlResult{manualResult("CIS-Azure-8.2",
			"Key Vault: purge protection enabled", "azurerm.keyvault", err)}
	}
	type vault struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Location   string `json:"location"`
		Properties struct {
			EnablePurgeProtection *bool `json:"enablePurgeProtection"`
		} `json:"properties"`
	}
	type listing struct {
		Value []vault `json:"value"`
	}
	var l listing
	_ = json.Unmarshal(body, &l)
	var out []ControlResult
	for _, v := range l.Value {
		ctrl := ControlResult{
			ControlID: "CIS-Azure-8.2", Title: "Key Vault: purge protection enabled",
			Severity: "high", Region: v.Location, Resource: v.ID,
			Remediation: "az keyvault update --name " + v.Name + " --enable-purge-protection true",
		}
		if v.Properties.EnablePurgeProtection != nil && *v.Properties.EnablePurgeProtection {
			ctrl.Status = "pass"
		} else {
			ctrl.Status = "fail"
			ctrl.Evidence = "purge protection not enabled"
		}
		out = append(out, ctrl)
	}
	return out
}

func (a *AzureAdapter) checkKeyVaultRBAC(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-8.5", "Key Vault: RBAC over access policies",
		"Migrate to RBAC permission model: az keyvault update --enable-rbac-authorization true")
}

// ----- Defender for Cloud / Logging --------------------------------------

func (a *AzureAdapter) checkActivityLogRetention(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-5.1.1", "Activity log retention ≥ 365 days",
		"Configure diagnostic setting → Log Analytics workspace with 365-day retention.")
}

func (a *AzureAdapter) checkDiagnosticSettings(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-5.1.2", "Diagnostic settings configured for all resource types",
		"Audit `az monitor diagnostic-settings list` per resource.")
}

func (a *AzureAdapter) checkDefenderForServers(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-2.1.1", "Defender for Servers: standard tier",
		"az security pricing create --name VirtualMachines --tier Standard")
}

func (a *AzureAdapter) checkDefenderForKeyVault(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-2.1.7", "Defender for Key Vault: standard tier",
		"az security pricing create --name KeyVaults --tier Standard")
}

func (a *AzureAdapter) checkDefenderForAppService(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-2.1.4", "Defender for App Service: standard tier",
		"az security pricing create --name AppServices --tier Standard")
}

func (a *AzureAdapter) checkDefenderForContainerRegistry(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-2.1.6", "Defender for Container Registries: standard tier",
		"az security pricing create --name ContainerRegistry --tier Standard")
}

// ----- AppService ---------------------------------------------------------

func (a *AzureAdapter) checkAppServiceHTTPSOnly(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-9.1", "App Service: HTTPS-only enabled",
		"az webapp update --resource-group <rg> --name <app> --https-only true")
}

func (a *AzureAdapter) checkAppServiceManagedIdentity(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-9.4", "App Service: managed identity assigned",
		"az webapp identity assign --resource-group <rg> --name <app>")
}

func (a *AzureAdapter) checkAppServiceMinTLS(_ context.Context) ControlResult {
	return azureManual("CIS-Azure-9.3", "App Service: minimum TLS 1.2",
		"az webapp config set --min-tls-version 1.2")
}

// ----- helpers ------------------------------------------------------------

// azureManual emits a single Azure control result with status=manual.
// Used for controls where the API surface is intricate enough that
// auto-evaluation would be unreliable; we'd rather flag for review
// than silently mis-pass.
func azureManual(id, title, remediation string) ControlResult {
	return ControlResult{
		ControlID: id, Title: title, Severity: "medium",
		Status: "manual", Remediation: remediation,
		Evidence: "automated check not implemented; verify in Azure Portal",
	}
}
