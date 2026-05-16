// Package models defines shared canonical types used across services.
package models

import (
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Identity & RBAC
// ---------------------------------------------------------------------------

type User struct {
	ID          uuid.UUID  `json:"id"`
	PlatformID  uuid.UUID  `json:"platform_id"`
	PartnerID   *uuid.UUID `json:"partner_id,omitempty"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	Email       string     `json:"email"`
	FullName    string     `json:"full_name"`
	MFAEnabled  bool       `json:"mfa_enabled"`
	Status      string     `json:"status"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type Role struct {
	ID         uuid.UUID `json:"id"`
	Code       string    `json:"code"`
	Name       string    `json:"name"`
	ScopeLevel string    `json:"scope_level"`
}

type Permission struct {
	ID          uuid.UUID `json:"id"`
	Code        string    `json:"code"`
	Description string    `json:"description"`
}

// ---------------------------------------------------------------------------
// Multi-tenant hierarchy (Blueprint §9, §8.2)
// ---------------------------------------------------------------------------

type Platform struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Slug string    `json:"slug"`
}

type Partner struct {
	ID         uuid.UUID  `json:"id"`
	PlatformID uuid.UUID  `json:"platform_id"`
	ParentID   *uuid.UUID `json:"parent_id,omitempty"`
	TypeCode   string     `json:"type"`
	Name       string     `json:"name"`
	Slug       string     `json:"slug"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
}

type PartnerBranding struct {
	PartnerID         uuid.UUID `json:"partner_id"`
	ProductName       string    `json:"product_name"`
	LogoURL           string    `json:"logo_url"`
	FaviconURL        string    `json:"favicon_url"`
	PrimaryColor      string    `json:"primary_color"`
	SecondaryColor    string    `json:"secondary_color"`
	AccentColor       string    `json:"accent_color"`
	LegalFooter       string    `json:"legal_footer"`
	TermsOfService    string    `json:"terms_of_service"`
	PrivacyPolicy     string    `json:"privacy_policy"`
	SupportEmail      string    `json:"support_email"`
	SupportPhone      string    `json:"support_phone"`
	SenderEmail       string    `json:"sender_email"`
	SenderName        string    `json:"sender_name"`
	PdfCoverURL       string    `json:"pdf_cover_url"`
	WatermarkText     string    `json:"watermark_text"`
	ConfidentialityTag string   `json:"confidentiality_tag"`
}

type Tenant struct {
	ID            uuid.UUID `json:"id"`
	PlatformID    uuid.UUID `json:"platform_id"`
	PartnerID     uuid.UUID `json:"partner_id"`
	Name          string    `json:"name"`
	Slug          string    `json:"slug"`
	Status        string    `json:"status"`
	IsolationMode string    `json:"isolation_mode"`
	CreatedAt     time.Time `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Engagements & Scope (Blueprint §14)
// ---------------------------------------------------------------------------

type Engagement struct {
	ID          uuid.UUID  `json:"id"`
	PlatformID  uuid.UUID  `json:"platform_id"`
	PartnerID   uuid.UUID  `json:"partner_id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	ClientID    *uuid.UUID `json:"client_id,omitempty"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Status      string     `json:"status"`
	StartsAt    time.Time  `json:"starts_at"`
	EndsAt      time.Time  `json:"ends_at"`
	Intensity   string     `json:"intensity"`
	EmergencyContact struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Phone string `json:"phone"`
	} `json:"emergency_contact"`
	CreatedAt time.Time `json:"created_at"`
}

type ScopeTarget struct {
	ID            uuid.UUID  `json:"id"`
	EngagementID  uuid.UUID  `json:"engagement_id"`
	TargetType    string     `json:"target_type"`
	TargetValue   string     `json:"target_value"`
	Plane         string     `json:"plane"`
	Status        string     `json:"status"`
	ApprovedBy    *uuid.UUID `json:"approved_by,omitempty"`
	ApprovedAt    *time.Time `json:"approved_at,omitempty"`
	Notes         string     `json:"notes"`
	CreatedAt     time.Time  `json:"created_at"`
}

type AuthorizationDocument struct {
	ID            uuid.UUID  `json:"id"`
	EngagementID  uuid.UUID  `json:"engagement_id"`
	Title         string     `json:"title"`
	DocumentType  string     `json:"document_type"`
	StorageURL    string     `json:"storage_url"`
	SHA256        string     `json:"sha256"`
	SignedBy      string     `json:"signed_by"`
	SignedAt      *time.Time `json:"signed_at,omitempty"`
	UploadedAt    time.Time  `json:"uploaded_at"`
	Encrypted     bool       `json:"encrypted"`
}

// ---------------------------------------------------------------------------
// Assets (Blueprint §16)
// ---------------------------------------------------------------------------

type Asset struct {
	ID            uuid.UUID  `json:"id"`
	PlatformID    uuid.UUID  `json:"platform_id"`
	PartnerID     uuid.UUID  `json:"partner_id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	EngagementID  *uuid.UUID `json:"engagement_id,omitempty"`
	AssetType     string     `json:"asset_type"`
	Name          string     `json:"name"`
	Value         string     `json:"value"`
	Plane         string     `json:"plane"`
	Criticality   string     `json:"criticality"`
	Owner         string     `json:"owner"`
	Environment   string     `json:"environment"`
	CloudProvider string     `json:"cloud_provider"`
	Tags          []string   `json:"tags"`
	Metadata      map[string]any `json:"metadata"`
	DiscoveredVia string     `json:"discovered_via"`
	FirstSeen     time.Time  `json:"first_seen"`
	LastSeen      time.Time  `json:"last_seen"`
	CreatedAt     time.Time  `json:"created_at"`
}

// AssetType enumeration covering all 14 blueprint asset types.
var AssetTypes = []string{
	"domain", "subdomain", "ip", "cidr", "api", "webapp", "server",
	"database", "cloud_resource", "container", "k8s_cluster",
	"mobile_app", "repository", "ssl_certificate",
}

// CriticalityLevels are the 5 supported levels.
var CriticalityLevels = []string{"critical", "high", "medium", "low", "unknown"}

// ---------------------------------------------------------------------------
// Scan jobs (Blueprint §5, §6, §11)
// ---------------------------------------------------------------------------

type ScanJob struct {
	ID                uuid.UUID  `json:"id"`
	PlatformID        uuid.UUID  `json:"platform_id"`
	PartnerID         uuid.UUID  `json:"partner_id"`
	TenantID          uuid.UUID  `json:"tenant_id"`
	EngagementID      uuid.UUID  `json:"engagement_id"`
	ProfileID         uuid.UUID  `json:"profile_id"`
	ProfileCode       string     `json:"profile_code"`
	Plane             string     `json:"plane"`
	Region            string     `json:"region"`
	AgentID           *uuid.UUID `json:"agent_id,omitempty"`
	ScannerNodeID     *uuid.UUID `json:"scanner_node_id,omitempty"`
	Status            string     `json:"status"`
	TargetSummary     string     `json:"target_summary"`
	Targets           []string   `json:"targets"`
	ScheduleAt        *time.Time `json:"schedule_at,omitempty"`
	StartedAt         *time.Time `json:"started_at,omitempty"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	RequiresApproval  bool       `json:"requires_approval"`
	ApprovedBy        *uuid.UUID `json:"approved_by,omitempty"`
	ApprovedAt        *time.Time `json:"approved_at,omitempty"`
	JobSignature      string     `json:"job_signature,omitempty"`
	SigningKeyID      string     `json:"signing_key_id,omitempty"`
	RequestedBy       *uuid.UUID `json:"requested_by,omitempty"`
	CancellationReason string    `json:"cancellation_reason,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	// Tools is populated from scan_tasks when the scan_job is fetched
	// for an agent to execute — needed so the agent can rebuild the
	// canonical manifest the orchestrator signed.
	Tools             []string   `json:"tools,omitempty"`
}

type ScanProfile struct {
	ID               uuid.UUID `json:"id"`
	Code             string    `json:"code"`
	Name             string    `json:"name"`
	Plane            string    `json:"plane"`
	Intensity        string    `json:"intensity"`
	Description      string    `json:"description"`
	Tools            []string  `json:"tools"`
	Parameters       map[string]any `json:"parameters"`
	RequiresApproval bool      `json:"requires_approval"`
}

// ---------------------------------------------------------------------------
// Findings (Blueprint §17.2 canonical model)
// ---------------------------------------------------------------------------

type Finding struct {
	ID               uuid.UUID  `json:"id"`
	TenantID         uuid.UUID  `json:"tenant_id"`
	PartnerID        uuid.UUID  `json:"partner_id"`
	EngagementID     uuid.UUID  `json:"engagement_id"`
	AssetID          *uuid.UUID `json:"asset_id,omitempty"`
	ScanJobID        *uuid.UUID `json:"scan_job_id,omitempty"`
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	Severity         string     `json:"severity"`
	Confidence       string     `json:"confidence"`
	CVSSScore        float64    `json:"cvss_score"`
	CVSSVector       string     `json:"cvss_vector"`
	CWE              string     `json:"cwe"`
	CVE              string     `json:"cve"`
	Scanner          string     `json:"scanner"`
	ScanType         string     `json:"scan_type"`
	AffectedEndpoint string     `json:"affected_endpoint"`
	Port             int        `json:"port"`
	Protocol         string     `json:"protocol"`
	EvidenceSummary  string     `json:"evidence_summary"`
	BusinessImpact   string     `json:"business_impact"`
	TechnicalImpact  string     `json:"technical_impact"`
	Remediation      string     `json:"remediation"`
	References       []string   `json:"references"`
	Status           string     `json:"status"`
	AssignedTo       *uuid.UUID `json:"assigned_to,omitempty"`
	FirstSeen        time.Time  `json:"first_seen"`
	LastSeen         time.Time  `json:"last_seen"`
	DedupFingerprint string     `json:"dedup_fingerprint"`
}

// FindingStatuses lists the 11 lifecycle states from Blueprint §17.3.
var FindingStatuses = []string{
	"open", "triaged", "assigned", "in_progress", "risk_accepted",
	"false_positive", "remediated", "retest_requested", "retest_passed",
	"retest_failed", "closed",
}

// SeverityLevels in canonical order.
var SeverityLevels = []string{"critical", "high", "medium", "low", "info"}

// ---------------------------------------------------------------------------
// Evidence (Blueprint §18)
// ---------------------------------------------------------------------------

type Evidence struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	PartnerID      uuid.UUID  `json:"partner_id"`
	FindingID      *uuid.UUID `json:"finding_id,omitempty"`
	EngagementID   *uuid.UUID `json:"engagement_id,omitempty"`
	ScanJobID      *uuid.UUID `json:"scan_job_id,omitempty"`
	EvidenceType   string     `json:"evidence_type"`
	StorageURL     string     `json:"storage_url"`
	SHA256         string     `json:"sha256"`
	SizeBytes      int64      `json:"size_bytes"`
	ContentType    string     `json:"content_type"`
	Encrypted      bool       `json:"encrypted"`
	ImmutableUntil *time.Time `json:"immutable_until,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	UploadedAt     time.Time  `json:"uploaded_at"`
}

// ---------------------------------------------------------------------------
// Agents (Blueprint §13, §28)
// ---------------------------------------------------------------------------

type Agent struct {
	ID                  uuid.UUID  `json:"id"`
	PlatformID          uuid.UUID  `json:"platform_id"`
	PartnerID           uuid.UUID  `json:"partner_id"`
	TenantID            uuid.UUID  `json:"tenant_id"`
	Name                string     `json:"name"`
	Location            string     `json:"location"`
	FormFactor          string     `json:"form_factor"`
	Version             string     `json:"version"`
	Status              string     `json:"status"`
	LastHeartbeat       *time.Time `json:"last_heartbeat,omitempty"`
	CPUPercent          float64    `json:"cpu_percent"`
	MemoryPercent       float64    `json:"memory_percent"`
	CertStatus          string     `json:"cert_status"`
	CertExpiresAt       *time.Time `json:"cert_expires_at,omitempty"`
	EmergencyStopArmed  bool       `json:"emergency_stop_armed"`
	CreatedAt           time.Time  `json:"created_at"`
}

type AgentPolicy struct {
	AgentID              uuid.UUID `json:"agent_id"`
	TenantID             uuid.UUID `json:"tenant_id"`
	AllowedScopes        []string  `json:"allowed_scopes"`
	BlockedScopes        []string  `json:"blocked_scopes"`
	AllowedScanProfiles  []string  `json:"allowed_scan_profiles"`
	AllowedTools         []string  `json:"allowed_tools"`
	MaxConcurrentJobs    int       `json:"max_concurrent_jobs"`
	MaxCPUPercent        int       `json:"max_cpu_percent"`
	MaxMemoryPercent     int       `json:"max_memory_percent"`
	ScanWindowStart      string    `json:"scan_window_start"`
	ScanWindowEnd        string    `json:"scan_window_end"`
	DaysOfWeek           []string  `json:"days_of_week"`
	EmergencyStopEnabled bool      `json:"emergency_stop_enabled"`
}
