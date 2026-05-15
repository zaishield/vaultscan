// Package dashboards aggregates the data the executive, technical, and
// partner dashboards consume (Blueprint §7.4).
package dashboards

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Executive matches the 11 metrics in Blueprint §7.4.
type Executive struct {
	OverallRiskScore     float64        `json:"overall_risk_score"`
	TotalAssets          int            `json:"total_assets"`
	PubliclyExposed      int            `json:"publicly_exposed_assets"`
	InternalScanned      int            `json:"internal_assets_scanned"`
	CriticalFindings     int            `json:"critical_findings"`
	HighFindings         int            `json:"high_findings"`
	SLABreaches          int            `json:"sla_breaches"`
	RetestStatus         RetestStatus   `json:"retest_status"`
	ComplianceStatus     map[string]int `json:"compliance_status"`
	AgentHealth          AgentHealth    `json:"agent_health"`
	ScanTrend            []TrendBucket  `json:"scan_trend"`
}

type RetestStatus struct {
	Pending int `json:"pending"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
}

type AgentHealth struct {
	Online   int `json:"online"`
	Offline  int `json:"offline"`
	Pending  int `json:"pending"`
	Quarantined int `json:"quarantined"`
}

type TrendBucket struct {
	Date  string `json:"date"`
	Scans int    `json:"scans"`
}

func (s *Service) Executive(ctx context.Context, tenantID uuid.UUID) (*Executive, error) {
	x := &Executive{ComplianceStatus: map[string]int{}}
	row := s.pool.QueryRow(ctx, `
		SELECT
		  (SELECT COUNT(*) FROM assets WHERE tenant_id=$1),
		  (SELECT COUNT(*) FROM assets WHERE tenant_id=$1 AND plane='external'),
		  (SELECT COUNT(*) FROM assets WHERE tenant_id=$1 AND plane='internal' AND last_seen > now() - INTERVAL '30 days'),
		  (SELECT COUNT(*) FROM findings WHERE tenant_id=$1 AND severity='critical' AND status NOT IN ('closed','remediated','retest_passed','false_positive')),
		  (SELECT COUNT(*) FROM findings WHERE tenant_id=$1 AND severity='high'     AND status NOT IN ('closed','remediated','retest_passed','false_positive')),
		  (SELECT COUNT(*) FROM findings f WHERE f.tenant_id=$1
		      AND f.status NOT IN ('closed','remediated','retest_passed','false_positive')
		      AND f.last_seen < now() - INTERVAL '14 days' AND f.severity IN ('critical','high'))`,
		tenantID,
	)
	if err := row.Scan(&x.TotalAssets, &x.PubliclyExposed, &x.InternalScanned,
		&x.CriticalFindings, &x.HighFindings, &x.SLABreaches); err != nil {
		return nil, err
	}
	_ = s.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE status IN ('pending','assigned','in_progress')),
		  COUNT(*) FILTER (WHERE status='passed'),
		  COUNT(*) FILTER (WHERE status='failed')
		  FROM retest_requests r
		  JOIN findings f ON f.id = r.finding_id
		 WHERE f.tenant_id=$1`, tenantID).
		Scan(&x.RetestStatus.Pending, &x.RetestStatus.Passed, &x.RetestStatus.Failed)
	_ = s.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE status='online'),
		  COUNT(*) FILTER (WHERE status='offline'),
		  COUNT(*) FILTER (WHERE status='pending'),
		  COUNT(*) FILTER (WHERE status='quarantined')
		  FROM agents WHERE tenant_id=$1`, tenantID).
		Scan(&x.AgentHealth.Online, &x.AgentHealth.Offline, &x.AgentHealth.Pending, &x.AgentHealth.Quarantined)
	rows, err := s.pool.Query(ctx, `
		SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD'), COUNT(*)
		  FROM scan_jobs
		 WHERE tenant_id=$1 AND created_at > now() - INTERVAL '14 days'
		 GROUP BY 1 ORDER BY 1`, tenantID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t TrendBucket
			if err := rows.Scan(&t.Date, &t.Scans); err == nil {
				x.ScanTrend = append(x.ScanTrend, t)
			}
		}
	}
	x.OverallRiskScore = computeRiskScore(x)
	x.ComplianceStatus["iso27001_open"] = x.CriticalFindings + x.HighFindings
	x.ComplianceStatus["pci_open"] = x.CriticalFindings
	x.ComplianceStatus["soc2_open"] = x.SLABreaches
	return x, nil
}

func computeRiskScore(x *Executive) float64 {
	// Simple weighted composite, capped at 100.
	s := float64(x.CriticalFindings)*10 + float64(x.HighFindings)*5 + float64(x.SLABreaches)*7
	if s > 100 {
		return 100
	}
	return s
}

// Technical matches the 12 metric categories in Blueprint §7.4.
type Technical struct {
	BySeverity   map[string]int `json:"findings_by_severity"`
	ByAsset      []KV           `json:"findings_by_asset"`
	ByDomain     []KV           `json:"findings_by_domain"`
	ByScanner    map[string]int `json:"findings_by_scanner"`
	OpenPorts    int            `json:"open_ports"`
	ExposedSvcs  int            `json:"exposed_services"`
	TLSIssues    int            `json:"tls_issues"`
	ADRisks      int            `json:"ad_risks"`
	CloudPosture int            `json:"cloud_posture_risks"`
	ContainerRisks int          `json:"container_risks"`
	K8sRisks     int            `json:"k8s_risks"`
	WebAPIVulns  int            `json:"web_api_vulnerabilities"`
}

type KV struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func (s *Service) Technical(ctx context.Context, tenantID uuid.UUID) (*Technical, error) {
	t := &Technical{BySeverity: map[string]int{}, ByScanner: map[string]int{}}
	rows, _ := s.pool.Query(ctx,
		`SELECT severity, COUNT(*) FROM findings WHERE tenant_id=$1 GROUP BY severity`, tenantID)
	defer rows.Close()
	for rows.Next() {
		var k string
		var v int
		if err := rows.Scan(&k, &v); err == nil {
			t.BySeverity[k] = v
		}
	}
	asset, _ := s.pool.Query(ctx, `
		SELECT COALESCE(a.value, 'unassigned'), COUNT(*)
		  FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
		 WHERE f.tenant_id=$1
		 GROUP BY a.value ORDER BY COUNT(*) DESC LIMIT 10`, tenantID)
	defer asset.Close()
	for asset.Next() {
		var kv KV
		if err := asset.Scan(&kv.Key, &kv.Count); err == nil {
			t.ByAsset = append(t.ByAsset, kv)
		}
	}
	scanner, _ := s.pool.Query(ctx,
		`SELECT scanner, COUNT(*) FROM findings WHERE tenant_id=$1 GROUP BY scanner`, tenantID)
	defer scanner.Close()
	for scanner.Next() {
		var k string
		var v int
		if err := scanner.Scan(&k, &v); err == nil {
			t.ByScanner[k] = v
		}
	}
	_ = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE scan_type='network'),
		       COUNT(*) FILTER (WHERE scan_type='network' AND port > 0),
		       COUNT(*) FILTER (WHERE scan_type='tls'),
		       COUNT(*) FILTER (WHERE scan_type='ad'),
		       COUNT(*) FILTER (WHERE scan_type='cloud'),
		       COUNT(*) FILTER (WHERE scan_type='container'),
		       COUNT(*) FILTER (WHERE scan_type='kubernetes'),
		       COUNT(*) FILTER (WHERE scan_type IN ('web','template'))
		  FROM findings WHERE tenant_id=$1`, tenantID).
		Scan(&t.OpenPorts, &t.ExposedSvcs, &t.TLSIssues, &t.ADRisks,
			&t.CloudPosture, &t.ContainerRisks, &t.K8sRisks, &t.WebAPIVulns)
	return t, nil
}

// Partner dashboard matches the 8 metric categories in Blueprint §7.4.
type Partner struct {
	CustomersManaged          int          `json:"customers_managed"`
	ActiveTenants             int          `json:"active_tenants"`
	ActiveAgents              int          `json:"active_agents"`
	ScanUsage                 int          `json:"scan_usage_30d"`
	LicenseUsage              LicenseUsage `json:"license_usage"`
	OpenCriticalAcrossTenants int          `json:"open_critical_across_tenants"`
	ExpiringEngagements       int          `json:"expiring_engagements"`
	BillingCounters           map[string]int `json:"billing_counters"`
}
type LicenseUsage struct {
	AssetsUsed int `json:"assets_used"`
	ScansUsed  int `json:"scans_used"`
	AgentsUsed int `json:"agents_used"`
}

func (s *Service) Partner(ctx context.Context, partnerID uuid.UUID) (*Partner, error) {
	p := &Partner{BillingCounters: map[string]int{}}
	_ = s.pool.QueryRow(ctx, `
		SELECT
		  (SELECT COUNT(*) FROM tenants WHERE partner_id=$1),
		  (SELECT COUNT(*) FROM tenants WHERE partner_id=$1 AND status='active'),
		  (SELECT COUNT(*) FROM agents  WHERE partner_id=$1 AND status='online'),
		  (SELECT COUNT(*) FROM scan_jobs WHERE partner_id=$1 AND created_at > now() - INTERVAL '30 days'),
		  (SELECT COUNT(*) FROM assets WHERE partner_id=$1),
		  (SELECT COUNT(*) FROM agents  WHERE partner_id=$1),
		  (SELECT COUNT(*) FROM findings f
		     JOIN tenants t ON t.id = f.tenant_id
		    WHERE t.partner_id=$1 AND f.severity='critical'
		      AND f.status NOT IN ('closed','remediated','retest_passed','false_positive')),
		  (SELECT COUNT(*) FROM engagements
		     WHERE partner_id=$1 AND ends_at < now() + INTERVAL '14 days' AND status='active')`,
		partnerID).
		Scan(&p.CustomersManaged, &p.ActiveTenants, &p.ActiveAgents, &p.ScanUsage,
			&p.LicenseUsage.AssetsUsed, &p.LicenseUsage.AgentsUsed,
			&p.OpenCriticalAcrossTenants, &p.ExpiringEngagements)
	p.LicenseUsage.ScansUsed = p.ScanUsage
	p.BillingCounters["scans_30d"] = p.ScanUsage
	return p, nil
}

// keep import used for clarity even when no time-typed metric is exported yet
var _ = time.Time{}
