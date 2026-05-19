// push.go — APNS + FCM push notification dispatchers.
//
// Mobile devices register their push token via the §24 mobile portal
// API (POST /api/v1/mobile/devices). When the platform needs to push
// (critical finding alert, scan-job completion, emergency-stop
// confirmation), notify.Push.Send fans the message out to the
// registered devices via the right transport.
//
// APNS:  HTTP/2 with JWT authentication (provider key + key ID +
//        team ID). Endpoint api.push.apple.com.
// FCM:   HTTP/1 with OAuth2 service-account JWT bearer. Endpoint
//        fcm.googleapis.com/v1/projects/<project>/messages:send.
//
// Provider tokens auto-refresh; both are reused across calls.

package notify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/httputil"
)

// PushMessage is the abstract notification we want to deliver. The
// dispatcher renders it into APNS or FCM format depending on the
// device's platform.
type PushMessage struct {
	Title     string
	Body      string
	Badge     int
	Category  string            // APNS category / FCM "click_action"
	Severity  string
	Data      map[string]string // extra payload key/value
}

// Push is the dispatcher. Each transport is optional; nil-transport
// devices are skipped silently (logged elsewhere).
type Push struct {
	APNS *APNSTransport
	FCM  *FCMTransport
}

func (p *Push) Send(ctx context.Context, platform, deviceToken string, msg PushMessage) error {
	switch strings.ToLower(platform) {
	case "ios":
		if p.APNS == nil {
			return errors.New("push: APNS transport not configured")
		}
		return p.APNS.Send(ctx, deviceToken, msg)
	case "android":
		if p.FCM == nil {
			return errors.New("push: FCM transport not configured")
		}
		return p.FCM.Send(ctx, deviceToken, msg)
	default:
		return fmt.Errorf("push: unknown platform %q", platform)
	}
}

// ---- APNS ----------------------------------------------------------------

// APNSTransport speaks the modern APNS HTTP/2 API with JWT auth.
type APNSTransport struct {
	teamID     string
	keyID      string
	bundleID   string
	signingKey *ecdsa.PrivateKey
	endpoint   string  // https://api.push.apple.com OR https://api.sandbox.push.apple.com
	client     *http.Client

	tokMu      sync.Mutex
	cachedTok  string
	tokExpires time.Time
}

type APNSConfig struct {
	TeamID     string
	KeyID      string
	BundleID   string
	// PrivateKeyPEM is the EC-P256 .p8 file Apple gives you for the
	// APNs Auth Key (Identifiers → Keys → Apple Push Notifications service).
	PrivateKeyPEM string
	// Sandbox toggles between production + sandbox endpoints.
	Sandbox    bool
	HTTPClient *http.Client
}

func NewAPNSTransport(cfg APNSConfig) (*APNSTransport, error) {
	if cfg.TeamID == "" || cfg.KeyID == "" || cfg.BundleID == "" || cfg.PrivateKeyPEM == "" {
		return nil, errors.New("apns: TeamID, KeyID, BundleID, PrivateKeyPEM all required")
	}
	block, _ := pem.Decode([]byte(cfg.PrivateKeyPEM))
	if block == nil {
		return nil, errors.New("apns: PrivateKeyPEM not a valid PEM block")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apns: parse PKCS8: %w", err)
	}
	ec, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apns: key is not ECDSA (Apple .p8 keys are P-256)")
	}
	endpoint := "https://api.push.apple.com"
	if cfg.Sandbox {
		endpoint = "https://api.sandbox.push.apple.com"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		// Pin to httputil so we get TLS 1.2 floor via the central
		// Transport, redirect refusal, and air-gap allowlist
		// inheritance. APNS endpoints are vendor-controlled so the
		// hardening is mostly defense-in-depth — but the JWT
		// bearer payload is sensitive enough to warrant the floor.
		c := httputil.NewClient(httputil.Options{Timeout: 10 * time.Second})
		c.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		hc = c
	}
	return &APNSTransport{
		teamID: cfg.TeamID, keyID: cfg.KeyID, bundleID: cfg.BundleID,
		signingKey: ec, endpoint: endpoint, client: hc,
	}, nil
}

func (a *APNSTransport) token() (string, error) {
	a.tokMu.Lock()
	defer a.tokMu.Unlock()
	if a.cachedTok != "" && time.Now().Before(a.tokExpires) {
		return a.cachedTok, nil
	}
	header := map[string]string{"alg": "ES256", "kid": a.keyID, "typ": "JWT"}
	now := time.Now().UTC().Unix()
	payload := map[string]any{"iss": a.teamID, "iat": now}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(pb)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, a.signingKey, digest[:])
	if err != nil {
		return "", err
	}
	// JWT signature for ES256 is r||s, each padded to 32 bytes.
	rBytes := pad32(r.Bytes())
	sBytes := pad32(s.Bytes())
	sig := append(rBytes, sBytes...)
	jwt := signing + "." + base64.RawURLEncoding.EncodeToString(sig)
	a.cachedTok = jwt
	// Apple says provider tokens are valid for 1 hour. Refresh at 50min.
	a.tokExpires = time.Now().Add(50 * time.Minute)
	return jwt, nil
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// Send POSTs the APNS payload for one device token.
func (a *APNSTransport) Send(ctx context.Context, deviceToken string, msg PushMessage) error {
	tok, err := a.token()
	if err != nil {
		return err
	}
	payload := map[string]any{
		"aps": map[string]any{
			"alert": map[string]any{
				"title": msg.Title,
				"body":  msg.Body,
			},
			"badge":    msg.Badge,
			"sound":    "default",
			"category": msg.Category,
		},
	}
	for k, v := range msg.Data {
		payload[k] = v
	}
	body, _ := json.Marshal(payload)

	url := fmt.Sprintf("%s/3/device/%s", a.endpoint, deviceToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apns-topic", a.bundleID)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("authorization", "bearer "+tok)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// 410 Gone = device token invalid → caller can prune the device.
	if resp.StatusCode == http.StatusGone {
		return ErrDeviceTokenInvalid
	}
	return fmt.Errorf("apns %d: %s", resp.StatusCode, string(respBody))
}

// ErrDeviceTokenInvalid signals the caller (mobile.devices service)
// to mark the device as revoked + stop sending to it.
var ErrDeviceTokenInvalid = errors.New("push: device token invalid (410 Gone / NotRegistered)")

// ---- FCM ----------------------------------------------------------------

// FCMTransport speaks the FCM HTTP v1 API. Authenticated via a Google
// service-account JWT bearer (same SA-JWT pattern as the GCP cloud
// posture adapter).
type FCMTransport struct {
	projectID    string
	clientEmail  string
	privateKey   *rsa.PrivateKey
	privateKeyID string
	client       *http.Client

	tokMu     sync.Mutex
	cachedTok string
	tokExp    time.Time
}

type FCMConfig struct {
	// ServiceAccountJSON is the entire service-account key file
	// downloaded from Google Cloud Console. Same shape the GCP cloud
	// posture adapter uses.
	ServiceAccountJSON string
	HTTPClient         *http.Client
}

func NewFCMTransport(cfg FCMConfig) (*FCMTransport, error) {
	if cfg.ServiceAccountJSON == "" {
		return nil, errors.New("fcm: ServiceAccountJSON required")
	}
	var sa struct {
		ProjectID    string `json:"project_id"`
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		PrivateKeyID string `json:"private_key_id"`
	}
	if err := json.Unmarshal([]byte(cfg.ServiceAccountJSON), &sa); err != nil {
		return nil, fmt.Errorf("fcm: parse SA JSON: %w", err)
	}
	if sa.ProjectID == "" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("fcm: SA JSON missing project_id / client_email / private_key")
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("fcm: SA PEM invalid")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fcm: parse SA private key: %w", err)
	}
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("fcm: SA key is not RSA")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		c := httputil.NewClient(httputil.Options{Timeout: 10 * time.Second})
		c.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		hc = c
	}
	return &FCMTransport{
		projectID: sa.ProjectID, clientEmail: sa.ClientEmail,
		privateKey: rsaPriv, privateKeyID: sa.PrivateKeyID,
		client: hc,
	}, nil
}

func (f *FCMTransport) token(ctx context.Context) (string, error) {
	f.tokMu.Lock()
	defer f.tokMu.Unlock()
	if f.cachedTok != "" && time.Now().Before(f.tokExp) {
		return f.cachedTok, nil
	}
	now := time.Now().UTC()
	header := map[string]string{"alg": "RS256", "kid": f.privateKeyID, "typ": "JWT"}
	payload := map[string]any{
		"iss":   f.clientEmail,
		"scope": "https://www.googleapis.com/auth/firebase.messaging",
		"aud":   "https://oauth2.googleapis.com/token",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(pb)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	jwt := signing + "." + base64.RawURLEncoding.EncodeToString(sig)

	form := strings.NewReader("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + jwt)
	// Cap the OAuth exchange at 5s. The previous implementation
	// inherited only the caller's context, so a hung Google OAuth
	// endpoint would block every queued FCM.Send for the caller's
	// full ctx budget (potentially 30s+). 5s is generous against
	// the historical p95 (~200ms) and short enough that a
	// degraded oauth2.googleapis.com doesn't snowball into a
	// notify-worker deadlock.
	exchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(exchCtx, http.MethodPost,
		"https://oauth2.googleapis.com/token", form)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("fcm token %d: %s", resp.StatusCode, string(body))
	}
	var r struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", err
	}
	f.cachedTok = r.AccessToken
	f.tokExp = time.Now().Add(time.Duration(r.ExpiresIn-60) * time.Second)
	return r.AccessToken, nil
}

func (f *FCMTransport) Send(ctx context.Context, deviceToken string, msg PushMessage) error {
	tok, err := f.token(ctx)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{
		"message": map[string]any{
			"token": deviceToken,
			"notification": map[string]any{
				"title": msg.Title,
				"body":  msg.Body,
			},
			"data": msg.Data,
			"android": map[string]any{
				"priority": "high",
			},
		},
	})
	url := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", f.projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 404 ||
		strings.Contains(string(respBody), "NOT_FOUND") ||
		strings.Contains(string(respBody), "UNREGISTERED") {
		return ErrDeviceTokenInvalid
	}
	return fmt.Errorf("fcm %d: %s", resp.StatusCode, string(respBody))
}
