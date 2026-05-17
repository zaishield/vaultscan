// preferences.go — per-user notification preferences + on-call
// rotation lookup. Companion to service.go (which holds the SMTP /
// Twilio / PagerDuty transports).
//
// Resolution order at notify-fanout time:
//
//   1. If the event targets a specific user (e.g. an assigned
//      finding), look up that user's preferences for the event prefix.
//   2. If a tenant on-call schedule exists for the event class,
//      resolve the current on-call user via on_call_shifts.
//   3. Fall back to the tenant-level wired transports (legacy path).
//
// Quiet hours flip a channel from immediate→digest automatically;
// digest mode appends to notification_digest_queue rather than
// firing the transport. A separate cron drains the queue.

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Preferences encapsulates the DB-backed prefs lookup. Construct via
// NewPreferences in main; the per-request hot path calls
// ChannelsFor(ctx, userID, eventType, severity) → list of channels
// to fire (already filtered by quiet hours, mode=suppress, etc).
type Preferences struct {
	pool *pgxpool.Pool
}

func NewPreferences(pool *pgxpool.Pool) *Preferences { return &Preferences{pool: pool} }

// Channel is the resolved notification channel for one user+event.
type Channel struct {
	ID      uuid.UUID
	UserID  uuid.UUID
	Channel string  // slack | email | sms | push | pagerduty | webhook
	Address string  // routing target
	Mode    string  // immediate | digest | suppress
}

// ChannelsFor resolves the user's preferences for an event.
//   - Filters out channels where mode=suppress.
//   - Filters out channels where min_severity is higher than the
//     event severity.
//   - Promotes channels in quiet-hours window from immediate→digest.
func (p *Preferences) ChannelsFor(ctx context.Context, userID uuid.UUID,
	eventType, severity string, when time.Time,
) ([]Channel, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, user_id, event_prefix, min_severity, channel,
		       channel_address, mode, COALESCE(quiet_hours,'{}'::jsonb)
		  FROM notification_preferences
		 WHERE user_id = $1
		   AND enabled = true`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type pref struct {
		Channel
		eventPrefix string
		minSeverity string
		quietHours  []byte
	}
	var prefs []pref
	for rows.Next() {
		var pr pref
		if err := rows.Scan(&pr.ID, &pr.UserID, &pr.eventPrefix, &pr.minSeverity,
			&pr.Channel.Channel, &pr.Address, &pr.Mode, &pr.quietHours); err != nil {
			return nil, err
		}
		prefs = append(prefs, pr)
	}

	// Match longest event_prefix first.
	sort.Slice(prefs, func(i, j int) bool {
		return len(prefs[i].eventPrefix) > len(prefs[j].eventPrefix)
	})

	var out []Channel
	matched := map[string]bool{} // dedupe by channel kind — first match wins
	for _, pr := range prefs {
		if !matchesPrefix(pr.eventPrefix, eventType) {
			continue
		}
		if pr.minSeverity != "" && severityRank(severity) < severityRank(pr.minSeverity) {
			continue
		}
		if pr.Mode == "suppress" {
			continue
		}
		if matched[pr.Channel.Channel] {
			continue
		}
		matched[pr.Channel.Channel] = true
		// Quiet-hours promotion to digest.
		if inQuietHours(pr.quietHours, when) {
			pr.Mode = "digest"
		}
		out = append(out, pr.Channel)
	}
	return out, nil
}

// EnqueueDigest appends a digest entry; the digest cron drains it
// later into a single summary message per user per channel.
func (p *Preferences) EnqueueDigest(ctx context.Context, userID uuid.UUID,
	channel, eventType, severity string, payload map[string]any,
) error {
	body, _ := json.Marshal(payload)
	_, err := p.pool.Exec(ctx, `
		INSERT INTO notification_digest_queue(user_id, channel, event_type,
		    payload, severity)
		VALUES ($1, $2, $3, $4::jsonb, $5)`,
		userID, channel, eventType, body, nullIfEmptyString(severity))
	return err
}

// ---- On-call schedule resolution -----------------------------------------

// OnCallFor returns the user_id on shift for (tenantID, scheduleName)
// at `when`. Override shifts win over regular shifts. ErrNoOnCall when
// nobody is scheduled.
var ErrNoOnCall = errors.New("notify: no on-call user for that schedule + time")

func (p *Preferences) OnCallFor(ctx context.Context, tenantID uuid.UUID,
	scheduleName string, when time.Time,
) (uuid.UUID, error) {
	var (
		userID   uuid.UUID
		override bool
	)
	err := p.pool.QueryRow(ctx, `
		SELECT s.user_id, s.override
		  FROM on_call_shifts s
		  JOIN on_call_schedules sc ON sc.id = s.schedule_id
		 WHERE sc.tenant_id = $1
		   AND sc.name      = $2
		   AND $3 BETWEEN s.starts_at AND s.ends_at
		 ORDER BY s.override DESC, s.starts_at DESC
		 LIMIT 1`, tenantID, scheduleName, when).Scan(&userID, &override)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNoOnCall
		}
		return uuid.Nil, err
	}
	return userID, nil
}

// ---- helpers --------------------------------------------------------------

func matchesPrefix(prefix, eventType string) bool {
	if prefix == "*" || prefix == "" {
		return true
	}
	return strings.HasPrefix(eventType, prefix)
}

var sevRanks = map[string]int{
	"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

func severityRank(s string) int {
	return sevRanks[strings.ToLower(s)]
}

// quietHoursSpec is the JSON shape of preferences.quiet_hours.
//
// IMPORTANT: StartHour/EndHour describe the QUIET window — the
// hours during which the user does NOT want pushy notifications,
// only digests. The historical implementation inverted this and
// treated the same fields as "business hours" (quiet = outside),
// which made a 9-17 spec quiet OVERNIGHT — the opposite of any
// reasonable user intent. Fixed 2026-05; if downstream UIs were
// built against the inverted semantics, swap the values they
// submit.
type quietHoursSpec struct {
	Timezone    string `json:"timezone"`
	StartHour   int    `json:"start_hour"`
	EndHour     int    `json:"end_hour"`
	WeekdayOnly bool   `json:"weekday_only"` // quiet only on weekdays
}

// inQuietHours reports whether `when`, in the spec's timezone, falls
// INSIDE the quiet window (where notifications get digested).
func inQuietHours(specJSON []byte, when time.Time) bool {
	var spec quietHoursSpec
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		return false
	}
	if spec.Timezone == "" {
		return false
	}
	loc, err := time.LoadLocation(spec.Timezone)
	if err != nil {
		return false
	}
	t := when.In(loc)
	if spec.WeekdayOnly && (t.Weekday() == time.Saturday || t.Weekday() == time.Sunday) {
		// WeekdayOnly = "quiet hours apply only on weekdays". When
		// the current day is a weekend, no quiet window applies →
		// return false (not in quiet hours).
		return false
	}
	hour := t.Hour()
	if spec.StartHour <= spec.EndHour {
		// Same-day quiet window (e.g. start=22, end=23 → quiet only
		// for the 22:00 hour). The previous implementation returned
		// the inverse — "outside business hours" — which made a
		// 9-17 spec quiet OVERNIGHT, the opposite of what users set
		// it for. Quiet = [start, end).
		return hour >= spec.StartHour && hour < spec.EndHour
	}
	// Wrap-midnight quiet window (e.g. start=22, end=6 → quiet
	// from 22:00 through 05:59).
	return hour >= spec.StartHour || hour < spec.EndHour
}

func nullIfEmptyString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// keep import live for the few helpers above
var _ = fmt.Sprintf
