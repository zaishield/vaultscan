package enrichment

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CVEEnricher struct {
	pool *pgxpool.Pool
}

func NewCVEEnricher(pool *pgxpool.Pool) *CVEEnricher {
	return &CVEEnricher{pool: pool}
}

// ----- NVD ------------------------------------------------------------------

// NVDFeed is a minimal projection of the NVD JSON 1.1 feed. Only the
// fields we surface are typed; the rest stays out of the struct.
type NVDFeed struct {
	CVEItems []struct {
		CVE struct {
			Meta struct {
				ID string `json:"ID"`
			} `json:"CVE_data_meta"`
			Description struct {
				Data []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description_data"`
			} `json:"description"`
			References struct {
				Data []struct {
					URL string `json:"url"`
				} `json:"reference_data"`
			} `json:"references"`
		} `json:"cve"`
		Impact struct {
			V3 *struct {
				CVSSV3 struct {
					Version       string  `json:"version"`
					VectorString  string  `json:"vectorString"`
					BaseScore     float64 `json:"baseScore"`
					BaseSeverity  string  `json:"baseSeverity"`
				} `json:"cvssV3"`
			} `json:"baseMetricV3"`
		} `json:"impact"`
		PublishedDate    string `json:"publishedDate"`
		LastModifiedDate string `json:"lastModifiedDate"`
	} `json:"CVE_Items"`
}

// LoadNVD upserts CVSS-bearing CVEs into cve_metadata. The caller is
// responsible for gunzipping; we accept already-decoded JSON.
func (c *CVEEnricher) LoadNVD(ctx context.Context, body []byte) (int, error) {
	var feed NVDFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return 0, fmt.Errorf("cves: NVD JSON: %w", err)
	}
	loaded := 0
	for _, item := range feed.CVEItems {
		id := item.CVE.Meta.ID
		if id == "" {
			continue
		}
		var (
			score    *float64
			vector   *string
			severity *string
		)
		if item.Impact.V3 != nil {
			s := item.Impact.V3.CVSSV3.BaseScore
			v := item.Impact.V3.CVSSV3.VectorString
			sv := item.Impact.V3.CVSSV3.BaseSeverity
			score = &s
			vector = &v
			severity = &sv
		}
		summary := ""
		for _, d := range item.CVE.Description.Data {
			if d.Lang == "en" {
				summary = d.Value
				break
			}
		}
		refs := make([]string, 0, len(item.CVE.References.Data))
		for _, r := range item.CVE.References.Data {
			refs = append(refs, r.URL)
		}
		refJSON, _ := json.Marshal(refs)
		_, err := c.pool.Exec(ctx, `
			INSERT INTO cve_metadata(cve_id, cvss_score, cvss_vector, cvss_severity,
			    summary, "references", published_at, last_modified_at)
			VALUES ($1, $2, $3, $4, $5, $6::jsonb,
			        NULLIF($7,'')::timestamptz, NULLIF($8,'')::timestamptz)
			ON CONFLICT (cve_id) DO UPDATE
			   SET cvss_score   = COALESCE(EXCLUDED.cvss_score,   cve_metadata.cvss_score),
			       cvss_vector  = COALESCE(EXCLUDED.cvss_vector,  cve_metadata.cvss_vector),
			       cvss_severity= COALESCE(EXCLUDED.cvss_severity,cve_metadata.cvss_severity),
			       summary      = COALESCE(NULLIF(EXCLUDED.summary,''), cve_metadata.summary),
			       "references" = EXCLUDED."references",
			       last_modified_at = COALESCE(EXCLUDED.last_modified_at, cve_metadata.last_modified_at),
			       refreshed_at = now()`,
			id, score, vector, severity, summary, refJSON,
			item.PublishedDate, item.LastModifiedDate)
		if err != nil {
			return loaded, err
		}
		loaded++
	}
	return loaded, c.markFeedFresh(ctx, "nvd", loaded, nil)
}

// ----- EPSS ------------------------------------------------------------------

// LoadEPSS consumes the FIRST.org EPSS daily CSV. Skips comment lines
// (start with #) and the header row. Format: cve,epss,percentile.
func (c *CVEEnricher) LoadEPSS(ctx context.Context, body io.Reader) (int, error) {
	r := csv.NewReader(body)
	r.Comment = '#'
	loaded := 0
	header := false
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return loaded, fmt.Errorf("cves: EPSS csv: %w", err)
		}
		if len(rec) < 3 {
			continue
		}
		if !header {
			header = true
			if strings.EqualFold(rec[0], "cve") {
				continue
			}
		}
		cve := strings.TrimSpace(rec[0])
		score, err1 := strconv.ParseFloat(rec[1], 64)
		pct, err2 := strconv.ParseFloat(rec[2], 64)
		if err1 != nil || err2 != nil || cve == "" {
			continue
		}
		// EPSS rows can arrive before the NVD row exists (new CVE).
		// INSERT-then-update keeps the row creation simple.
		if _, err := c.pool.Exec(ctx, `
			INSERT INTO cve_metadata(cve_id, epss_score, epss_percentile, refreshed_at)
			VALUES ($1, $2, $3, now())
			ON CONFLICT (cve_id) DO UPDATE
			   SET epss_score      = EXCLUDED.epss_score,
			       epss_percentile = EXCLUDED.epss_percentile,
			       refreshed_at    = now()`,
			cve, score, pct); err != nil {
			return loaded, err
		}
		loaded++
	}
	return loaded, c.markFeedFresh(ctx, "epss", loaded, nil)
}

// ----- CISA KEV --------------------------------------------------------------

type KEVFeed struct {
	Vulnerabilities []struct {
		CveID            string `json:"cveID"`
		VendorProject    string `json:"vendorProject"`
		Product          string `json:"product"`
		VulnName         string `json:"vulnerabilityName"`
		DateAdded        string `json:"dateAdded"`
		ShortDescription string `json:"shortDescription"`
		RequiredAction   string `json:"requiredAction"`
		DueDate          string `json:"dueDate"`
		KnownRansomware  string `json:"knownRansomwareCampaignUse"` // "Known" / "Unknown"
	} `json:"vulnerabilities"`
}

// LoadKEV flags CISA-known-exploited CVEs. Many KEV entries arrive
// before NVD has scored them; this lets the platform act on them
// regardless of CVSS readiness.
func (c *CVEEnricher) LoadKEV(ctx context.Context, body []byte) (int, error) {
	var feed KEVFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return 0, fmt.Errorf("cves: KEV JSON: %w", err)
	}
	loaded := 0
	// Clear the flag first so retracted KEV entries lose the flag.
	if _, err := c.pool.Exec(ctx,
		`UPDATE cve_metadata SET kev_flagged=false, kev_ransomware=false, kev_due_date=NULL
		  WHERE kev_flagged=true`); err != nil {
		return 0, err
	}
	for _, v := range feed.Vulnerabilities {
		cve := strings.TrimSpace(v.CveID)
		if cve == "" {
			continue
		}
		ransomware := strings.EqualFold(v.KnownRansomware, "Known")
		_, err := c.pool.Exec(ctx, `
			INSERT INTO cve_metadata(cve_id, kev_flagged, kev_ransomware,
			    kev_due_date, summary, refreshed_at)
			VALUES ($1, true, $2, NULLIF($3,'')::date,
			        COALESCE(NULLIF($4,''), $5), now())
			ON CONFLICT (cve_id) DO UPDATE
			   SET kev_flagged     = true,
			       kev_ransomware  = EXCLUDED.kev_ransomware,
			       kev_due_date    = EXCLUDED.kev_due_date,
			       summary         = COALESCE(NULLIF(cve_metadata.summary,''), EXCLUDED.summary),
			       refreshed_at    = now()`,
			cve, ransomware, v.DueDate, v.ShortDescription, v.VulnName)
		if err != nil {
			return loaded, err
		}
		loaded++
	}
	return loaded, c.markFeedFresh(ctx, "kev", loaded, nil)
}

// ----- Enrichment-time lookup ----------------------------------------------

// EnrichmentResult is what the findings ingest path consults to decide
// whether to bump severity / mark SLA-overdue.
type EnrichmentResult struct {
	CVE           string
	CVSS          float64
	EPSS          float64
	EPSSPercentile float64
	KEV           bool
	KEVRansomware bool
	KEVDueDate    *time.Time
	Summary       string
}

// LookupCVE returns the enrichment metadata for a CVE id. Empty
// EnrichmentResult + nil error when the CVE is unknown — callers
// treat that as "nothing to bump".
func (c *CVEEnricher) LookupCVE(ctx context.Context, cve string) (*EnrichmentResult, error) {
	cve = strings.TrimSpace(strings.ToUpper(cve))
	if cve == "" {
		return &EnrichmentResult{}, nil
	}
	r := &EnrichmentResult{CVE: cve}
	var score, epss, pct *float64
	var due *time.Time
	err := c.pool.QueryRow(ctx, `
		SELECT cvss_score, epss_score, epss_percentile,
		       kev_flagged, kev_ransomware, kev_due_date, COALESCE(summary,'')
		  FROM cve_metadata WHERE cve_id = $1`, cve).
		Scan(&score, &epss, &pct, &r.KEV, &r.KEVRansomware, &due, &r.Summary)
	if err != nil {
		// Distinguish "row not found" (legitimate unknown) from
		// "DB error" (transient outage). Previously both returned
		// (&EnrichmentResult{}, nil), so a brief DB blip permanently
		// under-enriched a batch of findings — no retry signal and
		// no operator visibility. Now we propagate the error on
		// anything except pgx.ErrNoRows; callers can choose to
		// retry or fall back, and observability picks up the spike.
		if errors.Is(err, pgx.ErrNoRows) {
			return &EnrichmentResult{}, nil
		}
		return &EnrichmentResult{}, fmt.Errorf("enrichment: lookup %s: %w", cve, err)
	}
	if score != nil {
		r.CVSS = *score
	}
	if epss != nil {
		r.EPSS = *epss
	}
	if pct != nil {
		r.EPSSPercentile = *pct
	}
	r.KEVDueDate = due
	return r, nil
}

// SeverityBump translates an enrichment result into a severity uplift
// for an existing finding. Returns the new severity (or "" if no
// change). Drives the override engine in VS-07 — that engine already
// has a generic "promote severity" surface; this gives it data.
func (c *CVEEnricher) SeverityBump(currentSeverity string, e *EnrichmentResult) string {
	if e == nil || e.CVE == "" {
		return ""
	}
	// KEV trumps everything else.
	if e.KEV {
		return "critical"
	}
	// Very high EPSS percentile → bump to high.
	if e.EPSSPercentile >= 0.95 {
		if rank(currentSeverity) < rank("high") {
			return "high"
		}
	}
	// CVSS-derived bumps.
	switch {
	case e.CVSS >= 9.0 && rank(currentSeverity) < rank("critical"):
		return "critical"
	case e.CVSS >= 7.0 && rank(currentSeverity) < rank("high"):
		return "high"
	case e.CVSS >= 4.0 && rank(currentSeverity) < rank("medium"):
		return "medium"
	}
	return ""
}

func rank(s string) int {
	switch s {
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

func (c *CVEEnricher) markFeedFresh(ctx context.Context, name string, loaded int, lastErr error) error {
	errStr := ""
	if lastErr != nil {
		errStr = lastErr.Error()
	}
	_, err := c.pool.Exec(ctx, `
		UPDATE vuln_data_sources
		   SET last_polled_at = now(),
		       last_error = NULLIF($2,''),
		       rows_loaded = $3
		 WHERE name = $1`, name, errStr, loaded)
	return err
}
