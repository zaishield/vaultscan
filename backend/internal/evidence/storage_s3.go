// storage_s3.go — S3-compatible Storage backend.
//
// Works with anything that speaks the S3 REST API: AWS S3, MinIO,
// Ceph RGW, Backblaze B2, Cloudflare R2, Wasabi, DigitalOcean Spaces.
//
// Object key layout: tenants/<tenant_uuid>/<object_uuid>.enc
//
// Authentication: SigV4 (handled by internal/awssig). Credentials are
// supplied at construction; rotation is the operator's responsibility
// (re-create the Vault on a config reload).
//
// Quirks:
//   * Path-style addressing (https://endpoint/bucket/key) is used so
//     MinIO + Ceph + AWS all work without DNS-magic. Set
//     ForcePathStyle=false to use virtual-host addressing
//     (https://bucket.s3.amazonaws.com/key) for AWS S3.
//   * X-Amz-Server-Side-Encryption header is set to AES256 by default
//     so backends that support SSE-S3 add a second layer on top of
//     our envelope encryption.
package evidence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/awssig"
)

type S3Storage struct {
	endpoint       string  // https://s3.us-east-1.amazonaws.com or https://minio.local:9000
	bucket         string
	region         string
	backendLabel   string  // operator-configured label surfaced via Name()
	creds          awssig.Credentials
	httpClient     *http.Client
	forcePathStyle bool
	sseHeader      string  // "AES256" | "aws:kms" | ""
}

type S3Config struct {
	Endpoint        string  // required
	Bucket          string  // required
	Region          string  // default us-east-1
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string  // optional (STS)
	ForcePathStyle  bool    // default true (works with MinIO/AWS/Ceph)
	HTTPClient      *http.Client
	// BackendLabel surfaces via Storage.Name(). Operators set this
	// to "minio" / "ceph" / "r2" so metrics tagged `backend=` match
	// reality; defaults to "s3" when empty.
	BackendLabel    string
	// SSEHeader, if set, populates X-Amz-Server-Side-Encryption on PUT.
	// "" disables; "AES256" enables SSE-S3; "aws:kms" enables SSE-KMS
	// (requires SSEKMSKeyID).
	SSEHeader string
}

func NewS3Storage(c S3Config) (*S3Storage, error) {
	if c.Endpoint == "" {
		return nil, errors.New("evidence: S3 endpoint required")
	}
	if c.Bucket == "" {
		return nil, errors.New("evidence: S3 bucket required")
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return nil, errors.New("evidence: S3 credentials required")
	}
	region := c.Region
	if region == "" {
		region = "us-east-1"
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	label := c.BackendLabel
	if label == "" {
		label = "s3"
	}
	return &S3Storage{
		endpoint:       strings.TrimRight(c.Endpoint, "/"),
		bucket:         c.Bucket,
		region:         region,
		backendLabel:   label,
		creds:          awssig.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken},
		httpClient:     httpClient,
		forcePathStyle: c.ForcePathStyle,
		sseHeader:      c.SSEHeader,
	}, nil
}

func (s *S3Storage) Name() string { return s.backendLabel }

func (s *S3Storage) objectKey(tenantID, objectID uuid.UUID) string {
	return fmt.Sprintf("tenants/%s/%s.enc", tenantID, objectID)
}

func (s *S3Storage) objectURL(key string) string {
	if s.forcePathStyle {
		return fmt.Sprintf("%s/%s/%s", s.endpoint, s.bucket, key)
	}
	// virtual-host style: https://<bucket>.<host>/<key>
	// Only safe when the endpoint is *.amazonaws.com or another DNS that
	// resolves <bucket>.<host>.
	return fmt.Sprintf("https://%s.%s/%s", s.bucket, hostFromURL(s.endpoint), key)
}

func hostFromURL(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(u, "/:"); i > 0 {
		return u[:i]
	}
	return u
}

func (s *S3Storage) Put(ctx context.Context, tenantID, objectID uuid.UUID, blob []byte) error {
	key := s.objectKey(tenantID, objectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.objectURL(key), bytes.NewReader(blob))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(blob))
	req.Header.Set("Content-Type", "application/octet-stream")
	if s.sseHeader != "" {
		req.Header.Set("X-Amz-Server-Side-Encryption", s.sseHeader)
	}
	if err := awssig.Sign(req, s.region, "s3", s.creds); err != nil {
		return err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("s3 put %s: %d %s", key, resp.StatusCode, string(body))
	}
	return nil
}

func (s *S3Storage) Get(ctx context.Context, tenantID, objectID uuid.UUID) ([]byte, error) {
	key := s.objectKey(tenantID, objectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.objectURL(key), nil)
	if err != nil {
		return nil, err
	}
	if err := awssig.Sign(req, s.region, "s3", s.creds); err != nil {
		return nil, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: s3://%s/%s", ErrObjectNotFound, s.bucket, key)
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("s3 get %s: %d %s", key, resp.StatusCode, string(body))
	}
	// Cap reads at 256 MiB — evidence blobs are typically <10 MiB; a
	// runaway read shouldn't OOM the API pod.
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

func (s *S3Storage) Delete(ctx context.Context, tenantID, objectID uuid.UUID) error {
	key := s.objectKey(tenantID, objectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.objectURL(key), nil)
	if err != nil {
		return err
	}
	if err := awssig.Sign(req, s.region, "s3", s.creds); err != nil {
		return err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// S3 returns 204 No Content on successful delete; 404 is also OK.
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("s3 delete %s: %d %s", key, resp.StatusCode, string(body))
	}
	return nil
}
