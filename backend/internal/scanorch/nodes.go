package scanorch

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NodeOps owns the operational surface of the external scanner farm:
// heartbeats, auto-failover, per-region quotas, image-pull credentials, and
// the network policy renderer. It runs alongside Orchestrator inside the API
// process (admins call it) AND inside each scanner-worker (it Heartbeats).
type NodeOps struct {
	pool *pgxpool.Pool

	// StaleAfter controls how old a node's last heartbeat can get before
	// FailoverStalled marks it degraded. Default 2 minutes — production
	// can raise this for satellite-uplink regions.
	StaleAfter time.Duration

	// FailureThreshold: consecutive_failures >= this auto-degrades a node.
	FailureThreshold int

	// masterKey wraps pull-credential secrets at rest. Same scheme as the
	// evidence vault (AES-256-GCM with a 32-byte key). Nil = encryption
	// disabled (dev only — admin UI refuses to store credentials).
	masterKey []byte
}

func NewNodeOps(pool *pgxpool.Pool, masterKeyB64 string) (*NodeOps, error) {
	n := &NodeOps{
		pool:             pool,
		StaleAfter:       2 * time.Minute,
		FailureThreshold: 3,
	}
	if masterKeyB64 != "" {
		k, err := base64.StdEncoding.DecodeString(masterKeyB64)
		if err != nil {
			return nil, fmt.Errorf("scanorch: decode pull-cred key: %w", err)
		}
		if len(k) != 32 {
			return nil, errors.New("scanorch: pull-cred key must be 32 bytes")
		}
		n.masterKey = k
	}
	return n, nil
}

// ----- Heartbeat / health ----------------------------------------------------

type Heartbeat struct {
	NodeID           uuid.UUID
	InflightJobs     int
	LoadAvg          float64
	KernelVersion    string
	ScannerVersion   string
	ImagePullsFailed int
	LastError        string
}

// Record stamps the node's health row, resetting consecutive_failures if
// the report carries no error. If there *is* an error it bumps the counter
// — once it crosses FailureThreshold the next FailoverStalled run marks
// the node degraded.
func (n *NodeOps) RecordHeartbeat(ctx context.Context, hb Heartbeat) error {
	if hb.NodeID == uuid.Nil {
		return errors.New("scanorch: heartbeat without node id")
	}
	if hb.LastError == "" {
		_, err := n.pool.Exec(ctx, `
			INSERT INTO scanner_node_health(node_id, last_heartbeat_at,
			    inflight_jobs, load_avg, kernel_version, scanner_version,
			    image_pulls_failed, consecutive_failures, last_error, updated_at)
			VALUES ($1, now(), $2, $3, $4, $5, $6, 0, NULL, now())
			ON CONFLICT (node_id) DO UPDATE
			SET last_heartbeat_at = EXCLUDED.last_heartbeat_at,
			    inflight_jobs     = EXCLUDED.inflight_jobs,
			    load_avg          = EXCLUDED.load_avg,
			    kernel_version    = COALESCE(NULLIF(EXCLUDED.kernel_version,''),
			                                 scanner_node_health.kernel_version),
			    scanner_version   = COALESCE(NULLIF(EXCLUDED.scanner_version,''),
			                                 scanner_node_health.scanner_version),
			    image_pulls_failed= EXCLUDED.image_pulls_failed,
			    consecutive_failures = 0,
			    last_error        = NULL,
			    updated_at        = now()`,
			hb.NodeID, hb.InflightJobs, hb.LoadAvg, hb.KernelVersion,
			hb.ScannerVersion, hb.ImagePullsFailed)
		if err != nil {
			return err
		}
		// Heartbeat with no error also recovers a previously-degraded node.
		_, _ = n.pool.Exec(ctx, `
			UPDATE scanner_node_registry SET status='online', last_heartbeat=now()
			 WHERE id=$1 AND status='degraded'`, hb.NodeID)
		return nil
	}

	// Failure path — bump counter; auto-degrade once over threshold.
	_, err := n.pool.Exec(ctx, `
		INSERT INTO scanner_node_health(node_id, last_heartbeat_at, last_error,
		    consecutive_failures, image_pulls_failed, updated_at)
		VALUES ($1, now(), $2, 1, $3, now())
		ON CONFLICT (node_id) DO UPDATE
		SET last_heartbeat_at    = EXCLUDED.last_heartbeat_at,
		    last_error           = EXCLUDED.last_error,
		    image_pulls_failed   = EXCLUDED.image_pulls_failed,
		    consecutive_failures = scanner_node_health.consecutive_failures + 1,
		    updated_at           = now()`,
		hb.NodeID, hb.LastError, hb.ImagePullsFailed)
	if err != nil {
		return err
	}
	return n.degradeIfOverThreshold(ctx, hb.NodeID, hb.LastError)
}

func (n *NodeOps) degradeIfOverThreshold(ctx context.Context, nodeID uuid.UUID, reason string) error {
	var fails int
	if err := n.pool.QueryRow(ctx,
		`SELECT consecutive_failures FROM scanner_node_health WHERE node_id=$1`,
		nodeID).Scan(&fails); err != nil {
		return err
	}
	if fails < n.FailureThreshold {
		return nil
	}
	return n.markDegraded(ctx, nodeID, fmt.Sprintf("consecutive_failures=%d (%s)", fails, reason))
}

func (n *NodeOps) markDegraded(ctx context.Context, nodeID uuid.UUID, reason string) error {
	var region string
	if err := n.pool.QueryRow(ctx,
		`SELECT region FROM scanner_node_registry WHERE id=$1`, nodeID).Scan(&region); err != nil {
		return err
	}
	if _, err := n.pool.Exec(ctx,
		`UPDATE scanner_node_registry SET status='degraded' WHERE id=$1 AND status<>'degraded'`,
		nodeID); err != nil {
		return err
	}
	_, err := n.pool.Exec(ctx, `
		INSERT INTO scanner_node_failovers(node_id, region, reason, metadata)
		VALUES ($1, $2, $3, '{}'::jsonb)`, nodeID, region, reason)
	return err
}

// FailoverStalled scans the registry for nodes whose last heartbeat is older
// than StaleAfter and marks them degraded. Designed to be invoked from a
// periodic cron loop (every 30s). Returns the IDs that were degraded.
func (n *NodeOps) FailoverStalled(ctx context.Context) ([]uuid.UUID, error) {
	cutoff := time.Now().UTC().Add(-n.StaleAfter)
	rows, err := n.pool.Query(ctx, `
		SELECT r.id
		  FROM scanner_node_registry r
		  LEFT JOIN scanner_node_health h ON h.node_id = r.id
		 WHERE r.status = 'online'
		   AND COALESCE(h.last_heartbeat_at, r.last_heartbeat, '-infinity'::timestamptz) < $1`,
		cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var degraded []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		degraded = append(degraded, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range degraded {
		_ = n.markDegraded(ctx, id, "heartbeat stalled > "+n.StaleAfter.String())
	}
	return degraded, nil
}

// ----- Region quotas ---------------------------------------------------------

type RegionQuota struct {
	Region              string
	MaxConcurrentJobs   int
	ReservedForPlatform int
	Inflight            int
}

func (n *NodeOps) SetRegionQuota(ctx context.Context, region string, maxJobs, reserved int) error {
	if maxJobs <= 0 {
		return errors.New("scanorch: region quota must be > 0")
	}
	if reserved < 0 || reserved >= maxJobs {
		return errors.New("scanorch: reserved must be in [0, max)")
	}
	_, err := n.pool.Exec(ctx, `
		INSERT INTO scanner_region_quotas(region, max_concurrent_jobs, reserved_for_platform)
		VALUES ($1, $2, $3)
		ON CONFLICT (region) DO UPDATE
		   SET max_concurrent_jobs   = EXCLUDED.max_concurrent_jobs,
		       reserved_for_platform = EXCLUDED.reserved_for_platform,
		       updated_at = now()`,
		region, maxJobs, reserved)
	return err
}

// IsRegionAtQuota reports whether dispatching one more job into `region`
// would cross the cap. The picker uses this *before* allocating a job. The
// `platformTenant` flag exempts platform-owned tenants from the cap up to
// reserved_for_platform slots.
func (n *NodeOps) IsRegionAtQuota(ctx context.Context, region string, platformTenant bool) (bool, RegionQuota, error) {
	var q RegionQuota
	q.Region = region
	err := n.pool.QueryRow(ctx, `
		SELECT max_concurrent_jobs, reserved_for_platform
		  FROM scanner_region_quotas WHERE region=$1`, region).
		Scan(&q.MaxConcurrentJobs, &q.ReservedForPlatform)
	if err != nil {
		// No quota row = no cap.
		return false, q, nil
	}
	if err := n.pool.QueryRow(ctx, `
		SELECT count(*) FROM scan_jobs
		 WHERE plane='external' AND region=$1
		   AND status IN ('dispatched','running')`, region).Scan(&q.Inflight); err != nil {
		return false, q, err
	}
	cap := q.MaxConcurrentJobs
	if !platformTenant {
		cap -= q.ReservedForPlatform
	}
	return q.Inflight >= cap, q, nil
}

// EligibleNode picks the lowest-loaded healthy node in a region. Returns
// ErrNoHealthyNode if every node is offline/degraded or every node's last
// heartbeat is stale.
func (n *NodeOps) EligibleNode(ctx context.Context, region string) (uuid.UUID, error) {
	cutoff := time.Now().UTC().Add(-n.StaleAfter)
	q := `
		SELECT r.id
		  FROM scanner_node_registry r
		  LEFT JOIN scanner_node_health h ON h.node_id = r.id
		 WHERE r.status = 'online'
		   AND COALESCE(h.last_heartbeat_at, r.last_heartbeat, now()) >= $1`
	args := []any{cutoff}
	if region != "" {
		q += ` AND r.region = $2`
		args = append(args, region)
	}
	q += ` ORDER BY COALESCE(h.inflight_jobs, 0) ASC, COALESCE(h.load_avg, 0) ASC LIMIT 1`
	var id uuid.UUID
	if err := n.pool.QueryRow(ctx, q, args...).Scan(&id); err != nil {
		return uuid.Nil, ErrNoHealthyNode
	}
	return id, nil
}

var ErrNoHealthyNode = errors.New("scanorch: no healthy scanner node in region")
var ErrRegionAtQuota = errors.New("scanorch: region at concurrent-job quota")

// ----- Pull credentials ------------------------------------------------------

type PullCredential struct {
	ID           uuid.UUID
	Region       string
	RegistryHost string
	Username     string
	Password     string // cleartext only inside the process — never persisted
	RotatedAt    *time.Time
}

func (n *NodeOps) UpsertPullCredential(ctx context.Context, actor *uuid.UUID, in PullCredential) error {
	if n.masterKey == nil {
		return errors.New("scanorch: pull-credential encryption key not configured")
	}
	if in.Region == "" || in.RegistryHost == "" || in.Username == "" || in.Password == "" {
		return errors.New("scanorch: region+registry+username+password required")
	}
	ct, err := n.seal([]byte(in.Password))
	if err != nil {
		return err
	}
	_, err = n.pool.Exec(ctx, `
		INSERT INTO scanner_pull_credentials(region, registry_host, docker_username,
		    encrypted_secret, encryption_key_id, created_by)
		VALUES ($1, $2, $3, $4, 'platform-pull-v1', $5)
		ON CONFLICT (region, registry_host) DO UPDATE
		   SET docker_username   = EXCLUDED.docker_username,
		       encrypted_secret  = EXCLUDED.encrypted_secret,
		       encryption_key_id = EXCLUDED.encryption_key_id,
		       rotated_at        = now()`,
		in.Region, in.RegistryHost, in.Username, ct, actor)
	return err
}

func (n *NodeOps) GetPullCredential(ctx context.Context, region, registry string) (*PullCredential, error) {
	if n.masterKey == nil {
		return nil, errors.New("scanorch: pull-credential encryption key not configured")
	}
	var c PullCredential
	var ct []byte
	var keyID string
	err := n.pool.QueryRow(ctx, `
		SELECT id, region, registry_host, docker_username, encrypted_secret,
		       encryption_key_id, rotated_at
		  FROM scanner_pull_credentials
		 WHERE region=$1 AND registry_host=$2`,
		region, registry).
		Scan(&c.ID, &c.Region, &c.RegistryHost, &c.Username, &ct, &keyID, &c.RotatedAt)
	if err != nil {
		return nil, err
	}
	plain, err := n.open(ct)
	if err != nil {
		return nil, err
	}
	c.Password = string(plain)
	return &c, nil
}

// DockerConfigJSON renders the credential into the `.dockerconfigjson`
// format that Kubernetes consumes for image-pull secrets.
func (n *NodeOps) DockerConfigJSON(ctx context.Context, region, registry string) ([]byte, error) {
	c, err := n.GetPullCredential(ctx, region, registry)
	if err != nil {
		return nil, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(c.Username + ":" + c.Password))
	doc := map[string]any{
		"auths": map[string]any{
			registry: map[string]any{
				"username": c.Username,
				"password": c.Password,
				"auth":     auth,
			},
		},
	}
	return json.Marshal(doc)
}

// ----- AES-GCM helpers (matches evidence.Vault scheme) -----------------------

func (n *NodeOps) seal(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(n.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	return append(nonce, ct...), nil
}

func (n *NodeOps) open(blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(n.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("scanorch: ciphertext too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}

// ----- Network policy renderer -----------------------------------------------

type NetworkPolicyRule struct {
	Name      string
	CIDRs     []string
	Ports     []NetworkPolicyPort
	Direction string
}

type NetworkPolicyPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// LoadPolicies fetches every enabled policy for a region.
func (n *NodeOps) LoadPolicies(ctx context.Context, region string) ([]NetworkPolicyRule, error) {
	rows, err := n.pool.Query(ctx, `
		SELECT name, cidrs, ports, direction
		  FROM scanner_network_policies
		 WHERE region=$1 AND enabled=true
		 ORDER BY name`, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NetworkPolicyRule
	for rows.Next() {
		var r NetworkPolicyRule
		var cidrsRaw, portsRaw []byte
		if err := rows.Scan(&r.Name, &cidrsRaw, &portsRaw, &r.Direction); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(cidrsRaw, &r.CIDRs)
		_ = json.Unmarshal(portsRaw, &r.Ports)
		out = append(out, r)
	}
	return out, rows.Err()
}

// RenderNetworkPolicyYAML returns a Kubernetes NetworkPolicy manifest YAML
// that constrains scanner pods in `region` to the configured egress rules.
// Stable order (rules sorted by name, ports sorted by port) so the same
// inputs produce byte-identical output — easy to diff in PR review.
func (n *NodeOps) RenderNetworkPolicyYAML(ctx context.Context, region string) (string, error) {
	rules, err := n.LoadPolicies(ctx, region)
	if err != nil {
		return "", err
	}
	if len(rules) == 0 {
		return "", fmt.Errorf("scanorch: no network policies for region %q", region)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })

	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: networking.k8s.io/v1\n")
	fmt.Fprintf(&b, "kind: NetworkPolicy\n")
	fmt.Fprintf(&b, "metadata:\n")
	fmt.Fprintf(&b, "  name: vaultscan-scanners-%s\n", region)
	fmt.Fprintf(&b, "  namespace: vaultscan-scanners\n")
	fmt.Fprintf(&b, "spec:\n")
	fmt.Fprintf(&b, "  podSelector:\n")
	fmt.Fprintf(&b, "    matchLabels:\n")
	fmt.Fprintf(&b, "      app.kubernetes.io/name: vaultscan-scanner\n")
	fmt.Fprintf(&b, "      vaultscan.zaishield.com/region: %s\n", region)
	fmt.Fprintf(&b, "  policyTypes:\n")
	fmt.Fprintf(&b, "    - Egress\n")
	fmt.Fprintf(&b, "  egress:\n")
	for _, r := range rules {
		if r.Direction != "egress" {
			continue
		}
		fmt.Fprintf(&b, "    # %s\n", r.Name)
		fmt.Fprintf(&b, "    - to:\n")
		for _, c := range r.CIDRs {
			fmt.Fprintf(&b, "        - ipBlock:\n")
			fmt.Fprintf(&b, "            cidr: %s\n", c)
		}
		ports := append([]NetworkPolicyPort(nil), r.Ports...)
		sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
		fmt.Fprintf(&b, "      ports:\n")
		for _, p := range ports {
			fmt.Fprintf(&b, "        - protocol: %s\n", strings.ToUpper(p.Protocol))
			fmt.Fprintf(&b, "          port: %d\n", p.Port)
		}
	}
	return b.String(), nil
}
