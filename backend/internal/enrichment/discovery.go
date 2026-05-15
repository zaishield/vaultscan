// Package enrichment connects VAULTSCAN's asset/finding model to
// external data sources. §14 (discovery) + §16 (vulnerability) parts
// of the Blueprint.
//
// Each Import* method takes an already-fetched payload (the cron-runner
// owns the actual HTTP fetch + auth). This keeps the package
// network-policy-clean for unit tests.
package enrichment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DiscoveryEnricher struct {
	pool *pgxpool.Pool
}

func NewDiscoveryEnricher(pool *pgxpool.Pool) *DiscoveryEnricher {
	return &DiscoveryEnricher{pool: pool}
}

// ----- Shodan ----------------------------------------------------------------

// ShodanHost mirrors the relevant subset of the Shodan host result.
// We only consume what we'll actually surface; the full doc is huge.
type ShodanHost struct {
	IP        string   `json:"ip_str"`
	Hostnames []string `json:"hostnames"`
	Ports     []int    `json:"ports"`
	Org       string   `json:"org"`
	Country   string   `json:"location.country_name"`
	LastUpdate string  `json:"last_update"`
	Data      []struct {
		Port      int    `json:"port"`
		Transport string `json:"transport"`
		Product   string `json:"product"`
		Version   string `json:"version"`
		Banner    string `json:"data"`
	} `json:"data"`
}

// ImportShodan resolves each host against the tenant's known assets
// (by IP or hostname). Hits write asset_enrichments rows; misses are
// returned so the caller can decide whether to create a new asset
// row (auto-discovery) or just log.
func (d *DiscoveryEnricher) ImportShodan(ctx context.Context, tenantID uuid.UUID, hosts []ShodanHost) (matched, unmatched int, err error) {
	for _, h := range hosts {
		assetID, err := d.resolveAsset(ctx, tenantID, h.IP, h.Hostnames)
		if err != nil {
			return matched, unmatched, err
		}
		if assetID == uuid.Nil {
			unmatched++
			continue
		}
		matched++
		// open_ports — distilled list
		portsJSON, _ := json.Marshal(h.Ports)
		if err := d.upsertEnrichment(ctx, assetID, "shodan", "open_ports", portsJSON); err != nil {
			return matched, unmatched, err
		}
		// services — per-port (port, product, version, banner)
		services := make([]map[string]any, 0, len(h.Data))
		for _, s := range h.Data {
			services = append(services, map[string]any{
				"port":      s.Port,
				"transport": s.Transport,
				"product":   s.Product,
				"version":   s.Version,
				"banner":    truncate(s.Banner, 512),
			})
		}
		servicesJSON, _ := json.Marshal(services)
		if err := d.upsertEnrichment(ctx, assetID, "shodan", "services", servicesJSON); err != nil {
			return matched, unmatched, err
		}
		// organisation + country — useful for the "wait, this asset is
		// hosted by a third party we didn't know about" detection.
		metaJSON, _ := json.Marshal(map[string]string{"org": h.Org, "country": h.Country})
		if err := d.upsertEnrichment(ctx, assetID, "shodan", "metadata", metaJSON); err != nil {
			return matched, unmatched, err
		}
	}
	return matched, unmatched, nil
}

// ----- Censys -----------------------------------------------------------------

// CensysHost is the shape we pull from the Censys Hosts API.
type CensysHost struct {
	IP       string   `json:"ip"`
	Names    []string `json:"names"`
	Services []struct {
		Port            int    `json:"port"`
		ServiceName     string `json:"service_name"`
		TransportProto  string `json:"transport_protocol"`
		ExtractedTLS    map[string]any `json:"tls"`
		SoftwareVendor  string `json:"software_vendor"`
		SoftwareProduct string `json:"software_product"`
		SoftwareVersion string `json:"software_version"`
	} `json:"services"`
	LastUpdated string `json:"last_updated_at"`
}

// ImportCensys: parallel structure to Shodan; Censys's strength is
// per-port TLS metadata, so we land that under attribute='tls_certs'.
func (d *DiscoveryEnricher) ImportCensys(ctx context.Context, tenantID uuid.UUID, hosts []CensysHost) (matched, unmatched int, err error) {
	for _, h := range hosts {
		assetID, err := d.resolveAsset(ctx, tenantID, h.IP, h.Names)
		if err != nil {
			return matched, unmatched, err
		}
		if assetID == uuid.Nil {
			unmatched++
			continue
		}
		matched++
		services := make([]map[string]any, 0, len(h.Services))
		certs := make([]map[string]any, 0)
		for _, s := range h.Services {
			services = append(services, map[string]any{
				"port":            s.Port,
				"transport":       s.TransportProto,
				"service_name":    s.ServiceName,
				"software_vendor": s.SoftwareVendor,
				"software_product": s.SoftwareProduct,
				"software_version": s.SoftwareVersion,
			})
			if len(s.ExtractedTLS) > 0 {
				certs = append(certs, map[string]any{"port": s.Port, "tls": s.ExtractedTLS})
			}
		}
		svcJSON, _ := json.Marshal(services)
		if err := d.upsertEnrichment(ctx, assetID, "censys", "services", svcJSON); err != nil {
			return matched, unmatched, err
		}
		if len(certs) > 0 {
			certJSON, _ := json.Marshal(certs)
			if err := d.upsertEnrichment(ctx, assetID, "censys", "tls_certs", certJSON); err != nil {
				return matched, unmatched, err
			}
		}
	}
	return matched, unmatched, nil
}

// ----- Certificate Transparency logs -----------------------------------------

// CTEntry is one row from a CT-log fetcher (crt.sh JSON shape).
type CTEntry struct {
	CommonName  string   `json:"common_name"`
	SANNames    []string `json:"name_value"`  // crt.sh delivers as newline-joined
	Issuer      string   `json:"issuer_name"`
	Serial      string   `json:"serial_number"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	LogURL      string   `json:"entry_timestamp"`
}

// ImportCT writes new certificate observations + auto-discovers
// previously-unseen subdomains into the asset graph. Returns
// (newSubdomains, dedupHits) so the cron can metric the surge rate.
func (d *DiscoveryEnricher) ImportCT(ctx context.Context, tenantID uuid.UUID, entries []CTEntry) (newSubs, dedup int, err error) {
	for _, e := range entries {
		// crt.sh delivers SANs as a single string with embedded newlines.
		sans := splitSANs(e.SANNames, e.CommonName)
		sanJSON, _ := json.Marshal(sans)
		tag, err := d.pool.Exec(ctx, `
			INSERT INTO ct_log_entries(tenant_id, common_name, san_names, issuer,
			    serial, not_before, not_after, log_url)
			VALUES ($1, $2, $3::jsonb, $4, $5,
			        NULLIF($6,'')::timestamptz, NULLIF($7,'')::timestamptz, $8)
			ON CONFLICT (tenant_id, lower(common_name), COALESCE(serial,''))
			DO NOTHING`,
			tenantID, strings.ToLower(e.CommonName), sanJSON, e.Issuer,
			e.Serial, e.NotBefore, e.NotAfter, e.LogURL)
		if err != nil {
			return newSubs, dedup, err
		}
		if tag.RowsAffected() == 0 {
			dedup++
			continue
		}
		// New CT entry → check whether each SAN already exists as an
		// asset; if not, insert as a discovered subdomain.
		for _, name := range sans {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" || strings.HasPrefix(name, "*.") {
				continue
			}
			var existed bool
			if err := d.pool.QueryRow(ctx, `
				SELECT EXISTS(SELECT 1 FROM assets
				              WHERE tenant_id=$1 AND lower(value)=$2)`,
				tenantID, name).Scan(&existed); err != nil {
				continue
			}
			if existed {
				continue
			}
			if _, err := d.pool.Exec(ctx, `
				INSERT INTO assets(platform_id, partner_id, tenant_id, asset_type,
				    value, name, plane, criticality, discovered_via)
				SELECT t.platform_id, t.partner_id, t.id, 'subdomain', $2, $2,
				       'external', 'unknown', 'ct_log'
				  FROM tenants t WHERE t.id = $1
				ON CONFLICT DO NOTHING`,
				tenantID, name); err == nil {
				newSubs++
			}
		}
	}
	return newSubs, dedup, nil
}

// ----- Passive DNS ----------------------------------------------------------

type PassiveDNSRecord struct {
	Name      string `json:"name"`
	Type      string `json:"type"`   // A | AAAA | CNAME
	Value     string `json:"value"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Count     int    `json:"count"`
}

// ImportPassiveDNS adds the resolution history as enrichment attributes
// on the matching asset. Helps tell "old A record" vs "current A record".
func (d *DiscoveryEnricher) ImportPassiveDNS(ctx context.Context, tenantID uuid.UUID, records []PassiveDNSRecord) (int, error) {
	matched := 0
	for _, r := range records {
		assetID, err := d.resolveAsset(ctx, tenantID, "", []string{r.Name})
		if err != nil {
			return matched, err
		}
		if assetID == uuid.Nil {
			continue
		}
		matched++
		val, _ := json.Marshal(r)
		if err := d.upsertEnrichment(ctx, assetID, "passive_dns",
			"history:"+r.Type+":"+r.Value, val); err != nil {
			return matched, err
		}
	}
	return matched, nil
}

// ----- helpers ---------------------------------------------------------------

// resolveAsset finds an existing asset by IP or any of the given
// hostnames within the tenant. Returns uuid.Nil if not found.
func (d *DiscoveryEnricher) resolveAsset(ctx context.Context, tenantID uuid.UUID, ip string, hostnames []string) (uuid.UUID, error) {
	if ip != "" {
		var id uuid.UUID
		if err := d.pool.QueryRow(ctx, `
			SELECT id FROM assets
			 WHERE tenant_id=$1 AND value=$2 AND asset_type IN ('ip','cidr')
			 LIMIT 1`, tenantID, ip).Scan(&id); err == nil {
			return id, nil
		}
	}
	for _, h := range hostnames {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		var id uuid.UUID
		if err := d.pool.QueryRow(ctx, `
			SELECT id FROM assets
			 WHERE tenant_id=$1 AND lower(value)=$2
			 LIMIT 1`, tenantID, h).Scan(&id); err == nil {
			return id, nil
		}
	}
	return uuid.Nil, nil
}

func (d *DiscoveryEnricher) upsertEnrichment(ctx context.Context, assetID uuid.UUID, source, attr string, value []byte) error {
	_, err := d.pool.Exec(ctx, `
		INSERT INTO asset_enrichments(asset_id, source, attribute, value)
		VALUES ($1, $2, $3, $4::jsonb)
		ON CONFLICT (asset_id, source, attribute) DO UPDATE
		   SET value = EXCLUDED.value,
		       observed_at = now()`,
		assetID, source, attr, value)
	return err
}

func splitSANs(raw []string, cn string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(cn)
	for _, s := range raw {
		// crt.sh joins with \n; we tolerate both forms
		for _, line := range strings.Split(s, "\n") {
			add(line)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Ensure pkg is exercised by something — keep imports tidy.
var _ = errors.New
var _ time.Duration
var _ = fmt.Sprintf
