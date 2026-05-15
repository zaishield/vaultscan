package engagements

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// RulesOfEngagement is the legal-bounds document attached to every active
// engagement (Blueprint §14.5). The Scope Guard reads it on every scan
// submission to enforce techniques + time windows + intensity caps.
type RulesOfEngagement struct {
	ID                  uuid.UUID `json:"id"`
	EngagementID        uuid.UUID `json:"engagement_id"`
	AllowedTechniques   []string  `json:"allowed_techniques"`
	RestrictedTechniques []string `json:"restricted_techniques"`
	ScanWindowStart     string    `json:"scan_window_start,omitempty"`  // "HH:MM"
	ScanWindowEnd       string    `json:"scan_window_end,omitempty"`
	DaysOfWeek          []string  `json:"days_of_week"`                // ["mon","tue",...]
	MaxIntensity        string    `json:"max_intensity"`               // light|standard|aggressive
	NotifyEmails        []string  `json:"notify_emails"`
	Blackouts           []Blackout `json:"blackouts"`
	CreatedAt           time.Time  `json:"created_at"`
}

type Blackout struct {
	Label    string    `json:"label"`
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
}

// UpsertRoE creates or replaces the rules-of-engagement for an engagement.
func (s *Service) UpsertRoE(ctx context.Context, engagementID uuid.UUID, r RulesOfEngagement) error {
	if r.MaxIntensity == "" {
		r.MaxIntensity = "standard"
	}
	allowed, _ := json.Marshal(r.AllowedTechniques)
	restricted, _ := json.Marshal(r.RestrictedTechniques)
	dows, _ := json.Marshal(r.DaysOfWeek)
	emails, _ := json.Marshal(r.NotifyEmails)
	blackouts, _ := json.Marshal(r.Blackouts)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO rules_of_engagement(engagement_id, allowed_techniques,
		    restricted_techniques, scan_window_start, scan_window_end,
		    days_of_week, max_intensity, notify_emails, blackouts)
		VALUES ($1, $2::jsonb, $3::jsonb, NULLIF($4,'')::time, NULLIF($5,'')::time,
		        $6::jsonb, $7, $8::jsonb, $9::jsonb)`,
		engagementID, allowed, restricted, r.ScanWindowStart, r.ScanWindowEnd,
		dows, r.MaxIntensity, emails, blackouts)
	if err != nil {
		return fmt.Errorf("engagements: upsert roe: %w", err)
	}
	return nil
}

// GetRoE returns the most recent rules-of-engagement for an engagement.
func (s *Service) GetRoE(ctx context.Context, engagementID uuid.UUID) (*RulesOfEngagement, error) {
	var (
		r          RulesOfEngagement
		allowed, restricted, dows, emails, blackouts []byte
		startStr, endStr *string
	)
	if err := s.pool.QueryRow(ctx, `
		SELECT id, engagement_id, allowed_techniques, restricted_techniques,
		       to_char(scan_window_start, 'HH24:MI'), to_char(scan_window_end, 'HH24:MI'),
		       days_of_week, max_intensity, notify_emails, blackouts, created_at
		  FROM rules_of_engagement
		 WHERE engagement_id=$1
		 ORDER BY created_at DESC LIMIT 1`, engagementID).
		Scan(&r.ID, &r.EngagementID, &allowed, &restricted, &startStr, &endStr,
			&dows, &r.MaxIntensity, &emails, &blackouts, &r.CreatedAt); err != nil {
		return nil, err
	}
	if startStr != nil {
		r.ScanWindowStart = *startStr
	}
	if endStr != nil {
		r.ScanWindowEnd = *endStr
	}
	_ = json.Unmarshal(allowed, &r.AllowedTechniques)
	_ = json.Unmarshal(restricted, &r.RestrictedTechniques)
	_ = json.Unmarshal(dows, &r.DaysOfWeek)
	_ = json.Unmarshal(emails, &r.NotifyEmails)
	_ = json.Unmarshal(blackouts, &r.Blackouts)
	return &r, nil
}

// CheckBlackout returns nil if `now` is not inside any active blackout
// window for the engagement; otherwise returns an error naming the window.
// Scope Guard wires this so a Black-Friday blackout blocks every scan
// without needing operators to touch the daily window.
func (s *Service) CheckBlackout(ctx context.Context, engagementID uuid.UUID, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT blackouts FROM rules_of_engagement
		 WHERE engagement_id=$1 ORDER BY created_at DESC LIMIT 1`, engagementID).Scan(&raw)
	if err != nil {
		return nil // no RoE → no blackouts
	}
	var blackouts []Blackout
	_ = json.Unmarshal(raw, &blackouts)
	for _, b := range blackouts {
		if !b.StartsAt.After(now) && !b.EndsAt.Before(now) {
			return fmt.Errorf("blackout window active: %s (%s → %s)",
				b.Label, b.StartsAt.Format(time.RFC3339), b.EndsAt.Format(time.RFC3339))
		}
	}
	return nil
}

var _ = errors.New
