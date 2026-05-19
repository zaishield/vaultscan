package api

import (
	"fmt"
	"net/http"
	"time"
)

// securityTxtHandler serves an RFC 9116 security.txt at both
// /.well-known/security.txt and /security.txt. The body lists the
// disclosure contact, the policy URL, and the latest acceptable
// PGP-signing key fingerprint.
//
// Operator overrides via env vars (read at boot, baked into the
// returned string) so different deployments can ship different
// contact channels without code changes:
//
//   VAULTSCAN_SECURITY_CONTACT       = "mailto:security@your-org.example"
//   VAULTSCAN_SECURITY_POLICY_URL    = "https://your-org/security-policy"
//   VAULTSCAN_SECURITY_HIRING_URL    = "https://your-org/careers/security"
//   VAULTSCAN_SECURITY_ACK_URL       = "https://your-org/security-acknowledgements"
//   VAULTSCAN_SECURITY_PREFLANG      = "en"
//
// Defaults point at zaishield.com — operators on a white-label
// install MUST override.
func securityTxtHandler(s *Services) http.HandlerFunc {
	contact := s.Cfg.SecurityContact
	if contact == "" {
		contact = "mailto:security@zaishield.com"
	}
	policy := s.Cfg.SecurityPolicyURL
	if policy == "" {
		policy = "https://zaishield.com/security/policy"
	}
	hiring := s.Cfg.SecurityHiringURL
	if hiring == "" {
		hiring = "https://zaishield.com/careers"
	}
	ack := s.Cfg.SecurityAcknowledgementsURL
	if ack == "" {
		ack = "https://zaishield.com/security/acknowledgements"
	}
	preflang := s.Cfg.SecurityPreferredLanguage
	if preflang == "" {
		preflang = "en"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// RFC 9116 requires the Expires field. Compute it per-request
		// (12 months from now) so a long-lived pod doesn't end up
		// serving an expired security.txt — the previous boot-time
		// computation would expire if a pod ran for >12 months.
		expires := time.Now().UTC().Add(12 * 30 * 24 * time.Hour).Format(time.RFC3339)
		body := fmt.Sprintf(
			"Contact: %s\n"+
				"Expires: %s\n"+
				"Encryption: %s\n"+
				"Preferred-Languages: %s\n"+
				"Policy: %s\n"+
				"Hiring: %s\n"+
				"Acknowledgments: %s\n"+
				"Canonical: %s/.well-known/security.txt\n",
			contact,
			expires,
			policy+"/pgp",
			preflang,
			policy,
			hiring,
			ack,
			s.Cfg.APIPublicURL(),
		)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write([]byte(body))
	}
}
