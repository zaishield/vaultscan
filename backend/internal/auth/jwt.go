package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VaultscanClaims is the JWT shape minted by the platform / accepted from Keycloak.
type VaultscanClaims struct {
	jwt.RegisteredClaims
	Email       string   `json:"email"`
	FullName    string   `json:"name"`
	PlatformID  string   `json:"platform_id"`
	PartnerID   string   `json:"partner_id,omitempty"`
	TenantID    string   `json:"tenant_id,omitempty"`
	Roles       []string `json:"roles"`
	MFA         bool     `json:"mfa"`
}

type Verifier struct {
	sharedSecret []byte
	pool         *pgxpool.Pool
}

func NewVerifier(sharedSecret string, pool *pgxpool.Pool) *Verifier {
	return &Verifier{sharedSecret: []byte(sharedSecret), pool: pool}
}

func (v *Verifier) Parse(ctx context.Context, raw string) (*Identity, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
	if raw == "" {
		return nil, errors.New("auth: missing token")
	}
	claims := &VaultscanClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.sharedSecret, nil
	})
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("auth: invalid token: %w", err)
	}
	id := &Identity{
		Email:       claims.Email,
		FullName:    claims.FullName,
		Roles:       claims.Roles,
		MFAVerified: claims.MFA,
		Permissions: map[string]bool{},
	}
	if claims.Subject != "" {
		uid, err := uuid.Parse(claims.Subject)
		if err != nil {
			return nil, fmt.Errorf("auth: bad subject uuid: %w", err)
		}
		id.UserID = uid
	}
	if claims.PlatformID != "" {
		pid, err := uuid.Parse(claims.PlatformID)
		if err != nil {
			return nil, fmt.Errorf("auth: bad platform_id: %w", err)
		}
		id.PlatformID = pid
	}
	if claims.PartnerID != "" {
		pid, err := uuid.Parse(claims.PartnerID)
		if err == nil {
			id.PartnerID = &pid
		}
	}
	if claims.TenantID != "" {
		tid, err := uuid.Parse(claims.TenantID)
		if err == nil {
			id.TenantID = &tid
		}
	}
	if v.pool != nil {
		if err := v.loadPermissions(ctx, id); err != nil {
			return nil, err
		}
	}
	return id, nil
}

// IssueDevToken mints a development-only HS256 token. Production must use Keycloak.
func (v *Verifier) IssueDevToken(c VaultscanClaims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return tok.SignedString(v.sharedSecret)
}

func (v *Verifier) loadPermissions(ctx context.Context, id *Identity) error {
	if len(id.Roles) == 0 {
		return nil
	}
	rows, err := v.pool.Query(ctx, `
		SELECT DISTINCT p.code
		  FROM roles r
		  JOIN role_permissions rp ON rp.role_id = r.id
		  JOIN permissions p       ON p.id       = rp.permission_id
		 WHERE r.code = ANY($1)`, id.Roles)
	if err != nil {
		return fmt.Errorf("auth: load permissions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err == nil {
			id.Permissions[code] = true
		}
	}
	return rows.Err()
}
