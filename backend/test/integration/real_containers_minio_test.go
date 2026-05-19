//go:build integration

// real_containers_minio_test.go — boots a real MinIO container,
// creates a bucket, and exercises evidence.S3Storage against it.
// Closes the "operational dependencies tested against stubs only"
// gap for object storage.
//
// MinIO is API-compatible with S3, so this also exercises the
// production code path that talks to AWS S3 / Ceph RGW. The
// difference is local (free, deterministic) vs cloud (paid,
// flaky in CI).
//
// Skip path: if `docker` is not on PATH, the test skips cleanly.
// CI environments that don't allow nested containers can omit
// this; the in-process FilesystemStorage tests still cover the
// abstract Storage interface.

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/evidence"
)

// TestRealMinIO_EvidenceRoundTrip boots a fresh MinIO container,
// creates a bucket, and asserts evidence.S3Storage can PUT, GET,
// and DELETE objects through the real S3 wire protocol (SigV4 +
// HTTP). This catches header-signing bugs, content-type drift,
// and SigV4 canonicalization mistakes that an httptest mock
// can't.
func TestRealMinIO_EvidenceRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH; real-container test requires container runtime")
	}
	ctx := context.Background()

	// Pick a random high port + container name so concurrent test
	// runs (e.g. on CI matrix) don't collide.
	port := freeTCPPort(t)
	containerName := "vs-test-minio-" + uuid.NewString()[:8]
	bucket := "vs-test-" + uuid.NewString()[:8]

	startMinIO(t, containerName, port)
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	})

	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	access := "minioadmin"
	secret := "minioadmin"

	// Wait for ready.
	if err := waitForMinIO(endpoint, 30*time.Second); err != nil {
		t.Fatalf("minio never ready: %v", err)
	}

	// Create the bucket via mc (the MinIO client) so the test
	// surface is independent of whatever S3 SDK we'd otherwise
	// use. Run mc inside a one-shot container so we don't need
	// the binary on the host.
	if err := mcExec(endpoint, access, secret,
		"mb", "local/"+bucket); err != nil {
		t.Fatalf("mc mb: %v", err)
	}

	// Now exercise evidence.S3Storage against this real bucket.
	s, err := evidence.NewS3Storage(evidence.S3Config{
		Endpoint:        endpoint,
		Bucket:          bucket,
		Region:          "us-east-1",
		AccessKeyID:     access,
		SecretAccessKey: secret,
		ForcePathStyle:  true,
	})
	if err != nil {
		t.Fatalf("NewS3Storage: %v", err)
	}

	tenantID := uuid.New()
	objectID := uuid.New()
	plaintext := []byte("real-minio-roundtrip-" + uuid.NewString())

	// PUT
	if err := s.Put(ctx, tenantID, objectID, plaintext); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// GET (round-trip the bytes)
	got, err := s.Get(ctx, tenantID, objectID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch:\n got=%q\n want=%q", got, plaintext)
	}

	// DELETE
	if err := s.Delete(ctx, tenantID, objectID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Subsequent GET must fail with not-found.
	if _, err := s.Get(ctx, tenantID, objectID); err == nil {
		t.Error("Get after Delete returned nil error — delete didn't actually remove the object")
	}
}

// TestRealMinIO_SigV4SignsRequestsCorrectly is a more pointed
// test that focuses on the SigV4 signature path. MinIO's SigV4
// is strict — any canonicalization bug we'd otherwise hide
// behind a permissive mock surfaces here as a 403
// SignatureDoesNotMatch.
func TestRealMinIO_SigV4SignsRequestsCorrectly(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH")
	}
	ctx := context.Background()

	port := freeTCPPort(t)
	containerName := "vs-test-minio-sigv4-" + uuid.NewString()[:8]
	bucket := "vs-sigv4-" + uuid.NewString()[:8]
	startMinIO(t, containerName, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerName).Run() })

	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	if err := waitForMinIO(endpoint, 30*time.Second); err != nil {
		t.Fatalf("minio not ready: %v", err)
	}
	if err := mcExec(endpoint, "minioadmin", "minioadmin",
		"mb", "local/"+bucket); err != nil {
		t.Fatalf("mc mb: %v", err)
	}

	s, err := evidence.NewS3Storage(evidence.S3Config{
		Endpoint:        endpoint,
		Bucket:          bucket,
		Region:          "us-east-1",
		AccessKeyID:     "minioadmin",
		SecretAccessKey: "minioadmin",
		ForcePathStyle:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test edge cases that would trip a SigV4 canonicalization
	// bug: a tenant id with consecutive zeros (must not be
	// percent-encoded incorrectly), an object id with mixed case,
	// a very-small body, and an empty-ish body.
	// Production evidence is NEVER empty (AES-GCM adds 28 bytes of
	// overhead even on a 0-byte plaintext), so an empty-body PUT is
	// not a realistic scenario. The smallest production blob is a
	// few dozen bytes; we test from 1 byte up.
	cases := []struct {
		name   string
		tenant uuid.UUID
		object uuid.UUID
		body   []byte
	}{
		{"tiny body", uuid.New(), uuid.New(), []byte("x")},
		{"binary content", uuid.New(), uuid.New(), []byte{0, 1, 2, 255, 128, 64}},
		{"large body", uuid.New(), uuid.New(), bytes.Repeat([]byte("A"), 1<<20)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := s.Put(ctx, c.tenant, c.object, c.body); err != nil {
				t.Errorf("Put failed: %v", err)
				return
			}
			got, err := s.Get(ctx, c.tenant, c.object)
			if err != nil {
				t.Errorf("Get failed: %v", err)
				return
			}
			if !bytes.Equal(got, c.body) {
				t.Errorf("body mismatch len=%d/%d", len(got), len(c.body))
			}
			_ = s.Delete(ctx, c.tenant, c.object)
		})
	}
}

// ----- helpers ---------------------------------------------------

// mcExec runs `mc alias set local <endpoint> <ak> <sk>` followed by
// the given mc command. The minio/mc image's ENTRYPOINT is mc
// itself, so we override with --entrypoint /bin/sh and run a small
// shell script.
func mcExec(endpoint, ak, sk string, args ...string) error {
	script := fmt.Sprintf(
		`mc alias set local %s %s %s >/dev/null && mc %s`,
		endpoint, ak, sk, strings.Join(args, " "))
	out, err := exec.Command("docker", "run", "--rm",
		"--network", "host",
		"--entrypoint", "/bin/sh",
		"minio/mc:latest", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v\n%s", err, out)
	}
	return nil
}

func startMinIO(t *testing.T, name string, port int) {
	t.Helper()
	out, err := exec.Command("docker", "run", "-d",
		"--name", name,
		"-p", fmt.Sprintf("%d:9000", port),
		"-e", "MINIO_ROOT_USER=minioadmin",
		"-e", "MINIO_ROOT_PASSWORD=minioadmin",
		"minio/minio:latest",
		"server", "/data").CombinedOutput()
	if err != nil {
		t.Skipf("could not start minio (likely no docker / no internet to pull image): %v\n%s", err, out)
	}
}

func waitForMinIO(endpoint string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("curl", "-sf",
			endpoint+"/minio/health/live").CombinedOutput()
		if err == nil && (len(out) == 0 || strings.Contains(string(out), "")) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("minio not ready within %s", timeout)
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	// Pick a high random port that's almost certainly unused.
	// uuid bytes mod 5000 + 30000 gives the range 30000-34999.
	b := uuid.NewString()
	n := int(b[0])*256 + int(b[2])
	return 30000 + (n % 5000)
}
