package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ----------------- Similarity clustering -------------------------------------

// ClusterKey produces a fuzzy fingerprint that groups findings that are
// "the same family" — same scanner + same CVE + a trimmed title that
// strips port/url specifics. So "TLS 1.0 enabled on tcp/443" and
// "TLS 1.0 enabled on tcp/8443" both bucket into one cluster.
func ClusterKey(in IngestInput) string {
	title := strings.ToLower(in.Title)
	title = stripVariableTokens(title)
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s", in.Scanner, strings.ToUpper(in.CVE), title)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// stripVariableTokens removes things that change per-host: port numbers,
// IP addresses, hostnames-in-quotes. Keeps the human-recognisable
// "title family" intact.
var (
	portRe   = regexp.MustCompile(`\b(tcp|udp)?/?\d{1,5}\b`)
	ipRe     = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	uuidRe   = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	hostRe   = regexp.MustCompile(`\b[a-z0-9][a-z0-9-]*\.[a-z0-9-]+(\.[a-z0-9-]+)+\b`)
	wsRe     = regexp.MustCompile(`\s+`)
)

func stripVariableTokens(s string) string {
	// Order matters: strip the most-specific patterns first so they
	// aren't eaten by less-specific ones. UUIDs and IPs contain
	// digit groups that look like ports to portRe; if portRe runs
	// first it breaks the UUID into "#PORT-#PORT-#PORT-..." which
	// then doesn't match uuidRe — so two findings with different
	// embedded UUIDs would cluster to DIFFERENT keys instead of
	// the same. The 2026-05 audit pass added a test for this and
	// the order swap is the fix.
	s = uuidRe.ReplaceAllString(s, "#UUID")
	s = ipRe.ReplaceAllString(s, "#IP")
	s = hostRe.ReplaceAllString(s, "#HOST")
	s = portRe.ReplaceAllString(s, "#PORT")
	s = wsRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

type ClusterSummary struct {
	ID                  uuid.UUID `json:"id"`
	Key                 string    `json:"cluster_key"`
	RepresentativeTitle string    `json:"representative_title"`
	Scanner             string    `json:"scanner"`
	SeverityMax         string    `json:"severity_max"`
	MemberCount         int       `json:"member_count"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
}

// AttachCluster looks up (or creates) a cluster for a finding and links
// the row. Called from Upsert after the canonical insert.
func (s *Service) AttachCluster(ctx context.Context, findingID uuid.UUID, in IngestInput) (uuid.UUID, error) {
	key := ClusterKey(in)
	var clusterID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO finding_clusters(tenant_id, cluster_key, representative_title,
		    scanner, severity_max, member_count, last_seen)
		VALUES ($1, $2, $3, $4, $5, 1, now())
		ON CONFLICT (tenant_id, cluster_key) DO UPDATE
		   SET member_count = finding_clusters.member_count + 1,
		       severity_max = CASE
		           WHEN $6::int > $7::int THEN EXCLUDED.severity_max
		           ELSE finding_clusters.severity_max
		       END,
		       last_seen = now()
		RETURNING id`,
		in.TenantID, key, in.Title, in.Scanner, in.Severity,
		severityRank(in.Severity), severityRank("info")).
		Scan(&clusterID)
	if err != nil {
		return uuid.Nil, err
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE findings SET cluster_id=$2 WHERE id=$1`,
		findingID, clusterID); err != nil {
		return uuid.Nil, err
	}
	return clusterID, nil
}

func (s *Service) ListClusters(ctx context.Context, tenantID uuid.UUID) ([]ClusterSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, cluster_key, representative_title, scanner, severity_max,
		       member_count, first_seen, last_seen
		  FROM finding_clusters
		 WHERE tenant_id=$1
		 ORDER BY last_seen DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClusterSummary
	for rows.Next() {
		var c ClusterSummary
		if err := rows.Scan(&c.ID, &c.Key, &c.RepresentativeTitle, &c.Scanner,
			&c.SeverityMax, &c.MemberCount, &c.FirstSeen, &c.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// severityRank gives a numeric comparator (higher = worse).
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// ----------------- Severity overrides ----------------------------------------

type SeverityOverrideInput struct {
	Name          string `json:"name"`
	TitleRegex    string `json:"title_regex"`
	CVEPattern    string `json:"cve_pattern"`
	ScannerFilter string `json:"scanner_filter"`
	NewSeverity   string `json:"new_severity"`
	Reason        string `json:"reason"`
	Priority      int    `json:"priority"`
}

func (s *Service) AddSeverityOverride(ctx context.Context, tenantID uuid.UUID, actor *uuid.UUID, in SeverityOverrideInput) (uuid.UUID, error) {
	if in.NewSeverity == "" || (in.TitleRegex == "" && in.CVEPattern == "") {
		return uuid.Nil, errors.New("findings: severity override needs title_regex or cve_pattern and new_severity")
	}
	if in.TitleRegex != "" {
		if _, err := regexp.Compile(in.TitleRegex); err != nil {
			return uuid.Nil, fmt.Errorf("findings: invalid title_regex: %w", err)
		}
	}
	if in.Priority <= 0 {
		in.Priority = 100
	}
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO finding_severity_overrides(tenant_id, name, title_regex,
		    cve_pattern, scanner_filter, new_severity, reason, priority, created_by)
		VALUES ($1, $2, NULLIF($3,''), NULLIF($4,''), NULLIF($5,''), $6, $7, $8, $9)
		RETURNING id`,
		tenantID, in.Name, in.TitleRegex, in.CVEPattern, in.ScannerFilter,
		in.NewSeverity, in.Reason, in.Priority, actor).Scan(&id)
	return id, err
}

// ApplyOverrides returns the (possibly new) severity + the original
// severity that was overridden (or "" if no rule fired). Called from
// Upsert before the INSERT runs.
func (s *Service) ApplyOverrides(ctx context.Context, tenantID uuid.UUID, in IngestInput) (string, string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT title_regex, cve_pattern, scanner_filter, new_severity
		  FROM finding_severity_overrides
		 WHERE tenant_id=$1 AND enabled=true
		 ORDER BY priority ASC, created_at ASC`, tenantID)
	if err != nil {
		return in.Severity, "", err
	}
	defer rows.Close()
	for rows.Next() {
		var titleRE, cveP, scanner, sev *string
		if err := rows.Scan(&titleRE, &cveP, &scanner, &sev); err != nil {
			return in.Severity, "", err
		}
		if scanner != nil && *scanner != "" && *scanner != in.Scanner {
			continue
		}
		matchedCVE := cveP != nil && *cveP != "" && in.CVE != "" &&
			matchesCaseInsensitive(*cveP, in.CVE)
		matchedTitle := titleRE != nil && *titleRE != "" &&
			matchesCaseInsensitive(*titleRE, in.Title)
		if !matchedCVE && !matchedTitle {
			continue
		}
		// First rule wins. Record original severity for audit.
		return *sev, in.Severity, nil
	}
	return in.Severity, "", rows.Err()
}

func matchesCaseInsensitive(pattern, value string) bool {
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// ----------------- Suppression rules -----------------------------------------

type SuppressionInput struct {
	Name          string     `json:"name"`
	TitleRegex    string     `json:"title_regex"`
	CVEPattern    string     `json:"cve_pattern"`
	ScannerFilter string     `json:"scanner_filter"`
	AssetFilter   string     `json:"asset_filter"`
	Reason        string     `json:"reason"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

func (s *Service) AddSuppressionRule(ctx context.Context, tenantID uuid.UUID, actor *uuid.UUID, in SuppressionInput) (uuid.UUID, error) {
	if in.Reason == "" {
		return uuid.Nil, errors.New("findings: suppression reason required")
	}
	if in.TitleRegex == "" && in.CVEPattern == "" && in.ScannerFilter == "" {
		return uuid.Nil, errors.New("findings: suppression needs at least one pattern")
	}
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO finding_suppression_rules(tenant_id, name, title_regex,
		    cve_pattern, scanner_filter, asset_filter, reason, expires_at, created_by)
		VALUES ($1, $2, NULLIF($3,''), NULLIF($4,''), NULLIF($5,''),
		        NULLIF($6,''), $7, $8, $9)
		RETURNING id`,
		tenantID, in.Name, in.TitleRegex, in.CVEPattern, in.ScannerFilter,
		in.AssetFilter, in.Reason, in.ExpiresAt, actor).Scan(&id)
	return id, err
}

// EvaluateSuppression returns the rule id that matched, or uuid.Nil if no
// rule applies. The caller marks the finding's suppression_rule_id +
// transitions to 'false_positive' with an audit note.
func (s *Service) EvaluateSuppression(ctx context.Context, tenantID uuid.UUID, in IngestInput, assetValue string) (uuid.UUID, string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, title_regex, cve_pattern, scanner_filter, asset_filter, reason
		  FROM finding_suppression_rules
		 WHERE tenant_id=$1 AND enabled=true
		   AND (expires_at IS NULL OR expires_at > now())`, tenantID)
	if err != nil {
		return uuid.Nil, "", err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id      uuid.UUID
			titleRE, cveP, scanner, asset *string
			reason  string
		)
		if err := rows.Scan(&id, &titleRE, &cveP, &scanner, &asset, &reason); err != nil {
			return uuid.Nil, "", err
		}
		if scanner != nil && *scanner != "" && *scanner != in.Scanner {
			continue
		}
		// EVERY non-nil pattern field must match (AND semantics).
		ok := true
		if titleRE != nil && *titleRE != "" && !matchesCaseInsensitive(*titleRE, in.Title) {
			ok = false
		}
		if ok && cveP != nil && *cveP != "" {
			if in.CVE == "" || !matchesCaseInsensitive(*cveP, in.CVE) {
				ok = false
			}
		}
		if ok && asset != nil && *asset != "" {
			if assetValue == "" || !matchesCaseInsensitive(*asset, assetValue) {
				ok = false
			}
		}
		if !ok {
			continue
		}
		_, _ = s.pool.Exec(ctx,
			`UPDATE finding_suppression_rules SET hit_count = hit_count + 1 WHERE id=$1`, id)
		return id, reason, nil
	}
	return uuid.Nil, "", rows.Err()
}

// MarkSuppressed flips a finding to false_positive and records the rule
// that caused it. Idempotent — calling twice is a no-op.
func (s *Service) MarkSuppressed(ctx context.Context, findingID, ruleID uuid.UUID, reason string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE findings
		   SET status='false_positive',
		       suppression_rule_id=$2,
		       updated_at=now()
		 WHERE id=$1 AND status IN ('open','triaged')`, findingID, ruleID)
	if err != nil {
		return err
	}
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO finding_status_history(finding_id, from_status, to_status, note)
		VALUES ($1, 'open', 'false_positive', $2)`, findingID, "auto-suppressed: "+reason)
	return nil
}

// ----------------- SARIF export ---------------------------------------------

// SARIFExport returns a SARIF 2.1.0 JSON document covering every finding
// matching the filter. Grouped into one Run per scanner so external tools
// (GitHub code-scanning, CI gates) can attribute results correctly.
func (s *Service) SARIFExport(ctx context.Context, f ListFilter) ([]byte, error) {
	findings, err := s.List(ctx, f)
	if err != nil {
		return nil, err
	}
	// Bucket by scanner.
	byScanner := map[string][]sarifResult{}
	for _, fi := range findings {
		byScanner[fi.Scanner] = append(byScanner[fi.Scanner], sarifResult{
			RuleID:  ruleIDOf(fi.CVE, fi.CWE, fi.Title),
			Level:   sarifLevel(fi.Severity),
			Message: sarifMessage{Text: fi.Title},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysLoc{
					ArtifactLocation: sarifArtifactLoc{URI: fi.AffectedEndpoint},
				},
			}},
			Properties: sarifProps{
				Severity:   fi.Severity,
				CVE:        fi.CVE,
				CWE:        fi.CWE,
				CVSSScore:  fi.CVSSScore,
				Port:       fi.Port,
				Protocol:   fi.Protocol,
			},
		})
	}
	// Stable order.
	scanners := make([]string, 0, len(byScanner))
	for k := range byScanner {
		scanners = append(scanners, k)
	}
	sort.Strings(scanners)

	runs := make([]sarifRun, 0, len(scanners))
	for _, sc := range scanners {
		runs = append(runs, sarifRun{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           sc,
				InformationURI: "https://zaishield.com/vaultscan",
				Version:        "vaultscan-scanner",
			}},
			Results: byScanner[sc],
		})
	}
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    runs,
	}
	return json.MarshalIndent(doc, "", "  ")
}

func ruleIDOf(cve, cwe, title string) string {
	if cve != "" {
		return cve
	}
	if cwe != "" {
		return cwe
	}
	h := sha256.Sum256([]byte(strings.ToLower(title)))
	return "ZAI-" + hex.EncodeToString(h[:6])
}

func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	}
	return "none"
}

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri,omitempty"`
	Version        string `json:"version,omitempty"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties sarifProps      `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysLoc `json:"physicalLocation"`
}

type sarifPhysLoc struct {
	ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
}

type sarifArtifactLoc struct {
	URI string `json:"uri,omitempty"`
}

type sarifProps struct {
	Severity  string  `json:"severity,omitempty"`
	CVE       string  `json:"cve,omitempty"`
	CWE       string  `json:"cwe,omitempty"`
	CVSSScore float64 `json:"cvss_score,omitempty"`
	Port      int     `json:"port,omitempty"`
	Protocol  string  `json:"protocol,omitempty"`
}
