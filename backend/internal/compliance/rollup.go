// rollup.go — per-tenant per-framework compliance coverage view.
// Used by the customer-facing dashboard + the auditor's evidence
// pack. Snapshots persist to compliance_rollup_snapshots so the
// auditor can ask "what did our SOC2 coverage look like on Y-M-D?"

package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Rollup is the per-tenant view of a single framework's coverage.
type Rollup struct {
	Framework        string    `json:"framework"`
	FrameworkVersion string    `json:"framework_version"`
	ControlsTotal    int       `json:"controls_total"`
	ControlsPass     int       `json:"controls_pass"`
	ControlsFail     int       `json:"controls_fail"`
	ControlsManual   int       `json:"controls_manual"`
	CoveragePct      float64   `json:"coverage_pct"`     // pass / (pass+fail+manual) × 100
	EvaluatedAt      time.Time `json:"evaluated_at"`
	Breakdown        []ControlRollup `json:"breakdown,omitempty"`
}

// ControlRollup is per-control detail under a framework. Omitted
// from the bulk rollup; included when ?include=breakdown is set.
type ControlRollup struct {
	ControlCode string `json:"control_code"`
	Title       string `json:"title"`
	Status      string `json:"status"`          // pass | fail | manual | unevaluated
	Note        string `json:"note,omitempty"`
	EvaluatedAt *time.Time `json:"evaluated_at,omitempty"`
}

// RollupAll returns one Rollup per (framework, framework_version)
// for the tenant. `includeBreakdown=true` also fills the
// per-control breakdown.
func (e *Evaluator) RollupAll(ctx context.Context, tenantID uuid.UUID, includeBreakdown bool) ([]Rollup, error) {
	// Aggregate totals per framework + version. LEFT JOIN so a
	// framework with zero evidence yet still appears (everything
	// counts as 'unevaluated' which → 0% coverage).
	rows, err := e.pool.Query(ctx, `
		SELECT cc.framework, cc.framework_version,
		       COUNT(*) AS total,
		       COUNT(*) FILTER (WHERE ce.status = 'pass')   AS pass,
		       COUNT(*) FILTER (WHERE ce.status = 'fail')   AS fail,
		       COUNT(*) FILTER (WHERE ce.status = 'manual') AS manual,
		       MAX(ce.evaluated_at)                         AS last_eval
		  FROM compliance_controls cc
		  LEFT JOIN compliance_evidence ce
		    ON ce.control_id = cc.id AND ce.tenant_id = $1
		 GROUP BY cc.framework, cc.framework_version
		 ORDER BY cc.framework, cc.framework_version`,
		tenantID)
	if err != nil {
		return nil, fmt.Errorf("compliance: rollup query: %w", err)
	}
	defer rows.Close()

	out := []Rollup{}
	for rows.Next() {
		var r Rollup
		var lastEval *time.Time
		if err := rows.Scan(&r.Framework, &r.FrameworkVersion,
			&r.ControlsTotal, &r.ControlsPass, &r.ControlsFail, &r.ControlsManual,
			&lastEval); err != nil {
			return nil, err
		}
		evaluated := r.ControlsPass + r.ControlsFail + r.ControlsManual
		if evaluated > 0 {
			r.CoveragePct = float64(r.ControlsPass) * 100.0 / float64(evaluated)
		}
		if lastEval != nil {
			r.EvaluatedAt = *lastEval
		}
		out = append(out, r)
	}

	if includeBreakdown {
		for i := range out {
			bd, err := e.breakdown(ctx, tenantID, out[i].Framework, out[i].FrameworkVersion)
			if err != nil {
				return nil, err
			}
			out[i].Breakdown = bd
		}
	}
	return out, nil
}

func (e *Evaluator) breakdown(ctx context.Context, tenantID uuid.UUID, framework, version string) ([]ControlRollup, error) {
	rows, err := e.pool.Query(ctx, `
		SELECT cc.control_code, cc.title,
		       COALESCE(ce.status, 'unevaluated'),
		       COALESCE(ce.observation_note,''),
		       ce.evaluated_at
		  FROM compliance_controls cc
		  LEFT JOIN compliance_evidence ce
		    ON ce.control_id = cc.id AND ce.tenant_id = $1
		 WHERE cc.framework = $2 AND cc.framework_version = $3
		 ORDER BY cc.control_code`,
		tenantID, framework, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ControlRollup{}
	for rows.Next() {
		var c ControlRollup
		if err := rows.Scan(&c.ControlCode, &c.Title, &c.Status, &c.Note, &c.EvaluatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Snapshot persists a frozen view of the current rollup. Used by
// auditors who need a stable artefact to reference ("our SOC2
// posture as-of 2026-04-01"). Returns the persisted rollups.
func (e *Evaluator) Snapshot(ctx context.Context, tenantID uuid.UUID) ([]Rollup, error) {
	rollups, err := e.RollupAll(ctx, tenantID, true)
	if err != nil {
		return nil, err
	}
	for _, r := range rollups {
		bd, _ := json.Marshal(r.Breakdown)
		if _, err := e.pool.Exec(ctx, `
			INSERT INTO compliance_rollup_snapshots(tenant_id, framework, framework_ver,
			    controls_total, controls_pass, controls_fail, controls_manual,
			    coverage_pct, breakdown_json)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
			tenantID, r.Framework, r.FrameworkVersion,
			r.ControlsTotal, r.ControlsPass, r.ControlsFail, r.ControlsManual,
			r.CoveragePct, string(bd)); err != nil {
			return nil, fmt.Errorf("compliance: snapshot insert: %w", err)
		}
	}
	return rollups, nil
}
