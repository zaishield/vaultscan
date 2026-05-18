// saml.go — SP-initiated SAML 2.0 flow.
//
// Two endpoints:
//   GET  /api/v1/auth/sso/{tenant_slug}/saml/start
//     - resolves tenant + loads stored metadata_xml
//     - extracts IdP SSO URL + signing cert from metadata
//     - builds an AuthnRequest via auth.SAMLConfig.AuthnRequestURL
//     - drops a signed state cookie carrying tenant_id + return_to
//     - 302 redirects to the IdP
//
//   POST /api/v1/auth/sso/{tenant_slug}/saml/acs
//     - reads the state cookie + the SAMLResponse POST body
//     - validates the SAMLResponse signature + audience + conditions
//       via auth.SAMLConfig.ParseAndValidateResponse
//     - maps the assertion's attributes into VaultscanClaims
//     - mints a JWT
//     - 302 redirects to the state's return_to with the JWT in a
//       short-lived HTTP-only Secure cookie (or as a fragment if
//       the caller's return_to is a SPA route — controlled by query)

package ssoflow

import (
	"errors"
	"net/http"

	"github.com/zaishield/vaultscan/backend/internal/auth"
)

// SAMLStart handles the GET /saml/start endpoint.
func (s *Service) SAMLStart(w http.ResponseWriter, r *http.Request, tenantSlug string) {
	tenantID, cfg, err := s.resolveTenant(r.Context(), tenantSlug)
	if err != nil {
		s.respondFlowError(w, err)
		return
	}
	if cfg.ProviderType != "saml" {
		http.Error(w, `{"error":"provider_mismatch"}`, http.StatusBadRequest)
		return
	}
	if cfg.MetadataXML == "" {
		http.Error(w, `{"error":"saml_metadata_missing"}`, http.StatusBadRequest)
		return
	}

	ssoURL, certPEM, err := parseSAMLMetadata(cfg.MetadataXML)
	if err != nil {
		http.Error(w, `{"error":"saml_metadata_invalid"}`, http.StatusBadRequest)
		return
	}
	saml := &auth.SAMLConfig{
		SPEntityID: s.publicURL + "/sso/" + tenantSlug,
		SPACSURL:   s.publicURL + "/api/v1/auth/sso/" + tenantSlug + "/saml/acs",
		IdPSSOURL:  ssoURL,
		IdPCertPEM: certPEM,
	}

	// Build state — short-lived signed JWT carrying tenant_id +
	// return_to + an opaque flow ID. The IdP gets a SHORT opaque
	// relayState; the cookie carries the rest (preventing CSRF +
	// keeping the IdP-visible state small).
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}
	stateTok, err := s.signState(stateClaims{
		TenantID: tenantID.String(), Provider: "saml", ReturnTo: returnTo,
		RegisteredClaims: registeredExp(stateMaxAge),
	})
	if err != nil {
		http.Error(w, `{"error":"state_sign_failed"}`, http.StatusInternalServerError)
		return
	}
	s.setStateCookie(w, stateTok)

	url, err := saml.AuthnRequestURL("vss")
	if err != nil {
		http.Error(w, `{"error":"authn_request_build_failed"}`, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// SAMLACS handles the POST /saml/acs callback.
//
// Browser POSTs from the IdP, multipart/form-data or
// application/x-www-form-urlencoded, with `SAMLResponse` =
// base64-encoded XML. Plus our `RelayState` if we shipped one.
func (s *Service) SAMLACS(w http.ResponseWriter, r *http.Request, tenantSlug string) {
	// Strict body cap so a malicious IdP can't OOM us with a
	// gigabyte SAMLResponse.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"bad_form"}`, http.StatusBadRequest)
		return
	}
	stateRaw, err := s.readStateCookie(r)
	if err != nil {
		http.Error(w, `{"error":"state_missing"}`, http.StatusBadRequest)
		return
	}
	state, err := s.verifyState(stateRaw)
	if err != nil {
		http.Error(w, `{"error":"state_invalid"}`, http.StatusBadRequest)
		return
	}
	if state.Provider != "saml" {
		http.Error(w, `{"error":"provider_mismatch"}`, http.StatusBadRequest)
		return
	}

	tenantID, cfg, err := s.resolveTenant(r.Context(), tenantSlug)
	if err != nil {
		s.respondFlowError(w, err)
		return
	}
	if tenantID.String() != state.TenantID {
		http.Error(w, `{"error":"tenant_mismatch"}`, http.StatusBadRequest)
		return
	}

	ssoURL, certPEM, err := parseSAMLMetadata(cfg.MetadataXML)
	if err != nil {
		http.Error(w, `{"error":"saml_metadata_invalid"}`, http.StatusBadRequest)
		return
	}
	saml := &auth.SAMLConfig{
		SPEntityID: s.publicURL + "/sso/" + tenantSlug,
		SPACSURL:   s.publicURL + "/api/v1/auth/sso/" + tenantSlug + "/saml/acs",
		IdPSSOURL:  ssoURL,
		IdPCertPEM: certPEM,
	}

	samlResp := r.FormValue("SAMLResponse")
	if samlResp == "" {
		http.Error(w, `{"error":"missing_saml_response"}`, http.StatusBadRequest)
		return
	}
	assertion, err := saml.ParseAndValidateResponse(samlResp)
	if err != nil {
		http.Error(w, `{"error":"saml_validation_failed"}`, http.StatusUnauthorized)
		return
	}

	// Map attributes → claims → JWT.
	attrs := samlAttributesToMap(assertion)
	claims, err := s.mapClaims(r.Context(), tenantID, cfg, attrs)
	if err != nil {
		http.Error(w, `{"error":"claim_mapping_failed"}`, http.StatusBadRequest)
		return
	}
	tok, err := s.issueJWT(r.Context(), claims)
	if err != nil {
		http.Error(w, `{"error":"jwt_mint_failed"}`, http.StatusInternalServerError)
		return
	}

	s.clearStateCookie(w)
	s.finishFlow(w, r, state.ReturnTo, tok)
}

// samlAttributesToMap collapses the SAML assertion's attribute
// statements into the shape mapClaims expects:
// {"email": ["…"], "name": [...], "roles": [...]}.
func samlAttributesToMap(a *auth.SAMLAssertion) map[string][]string {
	out := map[string][]string{}
	if a == nil {
		return out
	}
	// Email + Subject are top-level on the assertion.
	if a.Email != "" {
		out["email"] = []string{a.Email}
	} else if a.Subject != "" {
		out["email"] = []string{a.Subject}
	}
	// Walk the raw Attributes map (already name → [values]).
	for name, values := range a.Attributes {
		out[name] = append(out[name], values...)
		switch name {
		case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			"emailAddress", "mail", "Email":
			out["email"] = append(out["email"], values...)
		case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
			"displayName", "name", "cn":
			out["name"] = append(out["name"], values...)
		case "http://schemas.xmlsoap.org/claims/Group",
			"groups", "memberOf", "Role", "roles":
			out["roles"] = append(out["roles"], values...)
		}
	}
	return out
}

// finishFlow drops the JWT in a session cookie + redirects to the
// caller's return_to. The portal reads the cookie via a /auth/exchange
// endpoint that swaps it for an in-memory JWT (kept out of XSS reach).
func (s *Service) finishFlow(w http.ResponseWriter, r *http.Request, returnTo, jwtTok string) {
	http.SetCookie(w, &http.Cookie{
		Name: "vaultscan_session", Value: jwtTok, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		MaxAge: 12 * 60 * 60, // 12h, matches JWT exp
	})
	if returnTo == "" {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// respondFlowError uniformly handles the resolveTenant errors so we
// don't leak whether the slug exists when SSO is disabled (both
// return 404 with the same body).
func (s *Service) respondFlowError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrTenantNotFound), errors.Is(err, ErrSSODisabled):
		http.Error(w, `{"error":"sso_unavailable"}`, http.StatusNotFound)
	default:
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
	}
}
