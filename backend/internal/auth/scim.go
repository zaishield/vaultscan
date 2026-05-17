// scim.go — SCIM 2.0 (RFC 7644) endpoints for IdP-driven user
// provisioning. Handles the 4 endpoints every major IdP (Okta,
// OneLogin, Azure AD, JumpCloud, Google Workspace) needs:
//
//   GET    /Users           list users (filtered)
//   POST   /Users           provision user
//   GET    /Users/{id}      read user
//   PUT    /Users/{id}      replace user (full)
//   PATCH  /Users/{id}      partial update (used by deprovisioning →
//                           IdP sets active=false; we soft-delete)
//   DELETE /Users/{id}      hard-delete (rarely used)
//
// Auth: bearer-token via Authorization header. The token is a
// per-tenant SCIM provisioning secret created in Settings → SSO.
// We DON'T mount this under /api/v1; it lives under /scim/v2 with
// its own middleware so the IdP doesn't need our regular JWT.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SCIMUser is the projection of an internal user we expose over SCIM.
type SCIMUser struct {
	Schemas    []string         `json:"schemas"`
	ID         string           `json:"id"`
	UserName   string           `json:"userName"`
	Active     bool             `json:"active"`
	Name       SCIMName         `json:"name"`
	Emails     []SCIMEmail      `json:"emails"`
	Meta       SCIMMeta         `json:"meta"`
}

type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type SCIMMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}

// SCIMServer holds the database pool. SCIM operations are tenant-
// scoped; the auth layer (BearerToken validation) injects the
// tenant_id into the request context via ContextWithIdentity.
type SCIMServer struct {
	pool *pgxpool.Pool
}

func NewSCIMServer(pool *pgxpool.Pool) *SCIMServer { return &SCIMServer{pool: pool} }

// HandleUsers dispatches by method. Mount with chi at /scim/v2/Users.
func (s *SCIMServer) HandleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listUsers(w, r)
	case http.MethodPost:
		s.createUser(w, r)
	default:
		s.scimError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// HandleUserByID handles /Users/{id} for GET/PUT/PATCH/DELETE.
func (s *SCIMServer) HandleUserByID(w http.ResponseWriter, r *http.Request, idStr string) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		s.scimError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.getUser(w, r, id)
	case http.MethodPut:
		s.replaceUser(w, r, id)
	case http.MethodPatch:
		s.patchUser(w, r, id)
	case http.MethodDelete:
		s.deleteUser(w, r, id)
	default:
		s.scimError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *SCIMServer) listUsers(w http.ResponseWriter, r *http.Request) {
	id, _ := FromContext(r.Context())
	if id == nil || id.TenantID == nil {
		s.scimError(w, http.StatusForbidden, "tenant context required")
		return
	}
	filter := r.URL.Query().Get("filter")
	users, err := s.queryUsers(r.Context(), *id.TenantID, filter)
	if err != nil {
		s.scimError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(users),
		"itemsPerPage": len(users),
		"startIndex":   1,
		"Resources":    users,
	}
	writeSCIM(w, http.StatusOK, resp)
}

func (s *SCIMServer) createUser(w http.ResponseWriter, r *http.Request) {
	id, _ := FromContext(r.Context())
	if id == nil || id.TenantID == nil {
		s.scimError(w, http.StatusForbidden, "tenant context required")
		return
	}
	var in SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.scimError(w, http.StatusBadRequest, "decode: "+err.Error())
		return
	}
	if in.UserName == "" {
		s.scimError(w, http.StatusBadRequest, "userName required")
		return
	}
	email := in.UserName
	for _, e := range in.Emails {
		if e.Primary {
			email = e.Value
			break
		}
	}
	newID := uuid.New()
	_, err := s.pool.Exec(r.Context(), `
		INSERT INTO users(id, tenant_id, email, full_name, status, created_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (tenant_id, email) DO UPDATE
		   SET full_name = EXCLUDED.full_name,
		       status    = EXCLUDED.status`,
		newID, *id.TenantID, email, in.Name.Formatted,
		statusFromActive(in.Active))
	if err != nil {
		s.scimError(w, http.StatusInternalServerError, err.Error())
		return
	}
	users, _ := s.queryUsers(r.Context(), *id.TenantID, "userName eq \""+email+"\"")
	if len(users) > 0 {
		writeSCIM(w, http.StatusCreated, users[0])
		return
	}
	writeSCIM(w, http.StatusCreated, SCIMUser{
		Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:      newID.String(), UserName: email, Active: in.Active,
		Name: in.Name, Emails: in.Emails,
	})
}

func (s *SCIMServer) getUser(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
	id, _ := FromContext(r.Context())
	if id == nil || id.TenantID == nil {
		s.scimError(w, http.StatusForbidden, "tenant context required")
		return
	}
	users, err := s.queryUsers(r.Context(), *id.TenantID, fmt.Sprintf("id eq %q", userID.String()))
	if err != nil {
		s.scimError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(users) == 0 {
		s.scimError(w, http.StatusNotFound, "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, users[0])
}

func (s *SCIMServer) replaceUser(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
	id, _ := FromContext(r.Context())
	if id == nil || id.TenantID == nil {
		s.scimError(w, http.StatusForbidden, "tenant context required")
		return
	}
	var in SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.scimError(w, http.StatusBadRequest, "decode: "+err.Error())
		return
	}
	email := in.UserName
	for _, e := range in.Emails {
		if e.Primary {
			email = e.Value
			break
		}
	}
	tag, err := s.pool.Exec(r.Context(), `
		UPDATE users
		   SET email = $2, full_name = $3, status = $4
		 WHERE id = $1 AND tenant_id = $5`,
		userID, email, in.Name.Formatted,
		statusFromActive(in.Active), *id.TenantID)
	if err != nil {
		s.scimError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		s.scimError(w, http.StatusNotFound, "user not found")
		return
	}
	s.getUser(w, r, userID)
}

// patchUser handles SCIM PATCH ops. Common case: IdP sets active=false
// to deprovision a leaver. We support that op + name/email ops.
func (s *SCIMServer) patchUser(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
	id, _ := FromContext(r.Context())
	if id == nil || id.TenantID == nil {
		s.scimError(w, http.StatusForbidden, "tenant context required")
		return
	}
	var patch struct {
		Schemas    []string `json:"schemas"`
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		s.scimError(w, http.StatusBadRequest, "decode: "+err.Error())
		return
	}
	for _, op := range patch.Operations {
		path := strings.ToLower(op.Path)
		switch path {
		case "active":
			var active bool
			_ = json.Unmarshal(op.Value, &active)
			if _, err := s.pool.Exec(r.Context(),
				`UPDATE users SET status=$1 WHERE id=$2 AND tenant_id=$3`,
				statusFromActive(active), userID, *id.TenantID); err != nil {
				s.scimError(w, http.StatusInternalServerError, err.Error())
				return
			}
		case "name.formatted":
			var v string
			_ = json.Unmarshal(op.Value, &v)
			_, _ = s.pool.Exec(r.Context(),
				`UPDATE users SET full_name=$1 WHERE id=$2 AND tenant_id=$3`,
				v, userID, *id.TenantID)
		}
	}
	s.getUser(w, r, userID)
}

func (s *SCIMServer) deleteUser(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
	id, _ := FromContext(r.Context())
	if id == nil || id.TenantID == nil {
		s.scimError(w, http.StatusForbidden, "tenant context required")
		return
	}
	// Soft-delete: keep the row for audit, mark deactivated.
	_, _ = s.pool.Exec(r.Context(),
		`UPDATE users SET status='deactivated' WHERE id=$1 AND tenant_id=$2`,
		userID, *id.TenantID)
	w.WriteHeader(http.StatusNoContent)
}

// queryUsers translates a SCIM filter into a SQL WHERE clause.
// Supports the operators most real-world IdPs (Okta, Azure AD,
// JumpCloud) emit: eq, sw, ew, co, pr. Multi-clause filters (AND/OR)
// are not supported — those IdPs that need them fall back to
// client-side filtering by passing no filter.
//
// Filter forms:
//
//	userName eq "alice@example.com"
//	userName sw "alice"        — starts with
//	userName ew "@example.com" — ends with
//	userName co "alice"        — contains
//	userName pr                — present (non-null, non-empty)
func (s *SCIMServer) queryUsers(ctx context.Context, tenantID uuid.UUID, filter string) ([]SCIMUser, error) {
	q := `SELECT id, email, COALESCE(full_name,''), status,
	             to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
	        FROM users WHERE tenant_id = $1`
	args := []any{tenantID}
	if filter != "" {
		field, op, value, err := parseSCIMFilter(filter)
		if err != nil {
			return nil, err
		}
		col := ""
		switch field {
		case "username", "email":
			col = "email"
		case "id":
			col = "id"
		case "name.formatted", "displayname":
			col = "full_name"
		default:
			return nil, fmt.Errorf("scim: filter on %q not supported", field)
		}
		switch op {
		case "eq":
			q += fmt.Sprintf(" AND %s = $%d", col, len(args)+1)
			args = append(args, value)
		case "sw":
			q += fmt.Sprintf(" AND %s ILIKE $%d", col, len(args)+1)
			args = append(args, scimLikeEscape(value)+"%")
		case "ew":
			q += fmt.Sprintf(" AND %s ILIKE $%d", col, len(args)+1)
			args = append(args, "%"+scimLikeEscape(value))
		case "co":
			q += fmt.Sprintf(" AND %s ILIKE $%d", col, len(args)+1)
			args = append(args, "%"+scimLikeEscape(value)+"%")
		case "pr":
			q += fmt.Sprintf(" AND %s IS NOT NULL AND %s <> ''", col, col)
		default:
			return nil, fmt.Errorf("scim: operator %q not supported", op)
		}
	}
	q += " ORDER BY email LIMIT 200"
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SCIMUser
	for rows.Next() {
		var (
			id, email, fullName, status, created string
		)
		if err := rows.Scan(&id, &email, &fullName, &status, &created); err != nil {
			return nil, err
		}
		out = append(out, SCIMUser{
			Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			ID:       id,
			UserName: email,
			Active:   activeFromStatus(status),
			Name:     SCIMName{Formatted: fullName},
			Emails:   []SCIMEmail{{Value: email, Primary: true, Type: "work"}},
			Meta: SCIMMeta{
				ResourceType: "User",
				Created:      created,
			},
		})
	}
	return out, nil
}

// ---- helpers --------------------------------------------------------------

func statusFromActive(active bool) string {
	if active {
		return "active"
	}
	return "deactivated"
}

func activeFromStatus(status string) bool { return status == "active" }

// parseSCIMFilter handles the operator vocabulary documented on
// queryUsers. Returns (field, op, value, err). For "pr" (present),
// the returned value is empty — the caller checks op=="pr" and
// emits IS NOT NULL.
//
// Order matters: "pr" must be checked first because it's a single-
// token operator; the others (eq/sw/ew/co) wrap a quoted value.
func parseSCIMFilter(filter string) (field, op, value string, err error) {
	f := strings.TrimSpace(filter)
	// "field pr" — presence test, no value
	if strings.HasSuffix(strings.ToLower(f), " pr") {
		field = strings.ToLower(strings.TrimSpace(f[:len(f)-3]))
		if field == "" {
			return "", "", "", errors.New("scim: empty field in filter")
		}
		return field, "pr", "", nil
	}
	for _, candidate := range []string{" eq ", " sw ", " ew ", " co "} {
		idx := strings.Index(strings.ToLower(f), candidate)
		if idx <= 0 {
			continue
		}
		field = strings.ToLower(strings.TrimSpace(f[:idx]))
		op = strings.TrimSpace(candidate)
		value = strings.Trim(strings.TrimSpace(f[idx+len(candidate):]), `"`)
		if field == "" {
			return "", "", "", errors.New("scim: empty field in filter")
		}
		return field, op, value, nil
	}
	return "", "", "", errors.New("scim: only eq/sw/ew/co/pr operators supported")
}

// scimLikeEscape escapes the LIKE wildcards `%` and `_` so a filter
// like userName co "100%" matches the literal string "100%" instead
// of "100<anything>".
func scimLikeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '%' || r == '_' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *SCIMServer) scimError(w http.ResponseWriter, status int, detail string) {
	writeSCIM(w, status, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  fmt.Sprintf("%d", status),
		"detail":  detail,
	})
}

func writeSCIM(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
