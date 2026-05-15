package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubK8s simulates the slice of the K8s API the K8sJobRunner uses:
//   POST /apis/batch/v1/namespaces/<ns>/jobs       → 201 Created
//   GET  /apis/batch/v1/namespaces/<ns>/jobs/<n>   → returns the staged status
//   GET  /api/v1/namespaces/<ns>/pods?labelSelector=job-name=<n> → 1 pod
//   GET  /api/v1/namespaces/<ns>/pods/<p>/log      → canned log bytes
//   DELETE /apis/batch/v1/namespaces/<ns>/jobs/<n> → 200
type stubK8s struct {
	mu          sync.Mutex
	createdJobs []string
	deletedJobs []string
	status      string // "succeeded" | "failed" | "active"
	log         string // body returned by /pods/<p>/log
	authSeen    []string
}

func newStubK8s(t *testing.T, status, log string) (*K8sJobRunner, *stubK8s) {
	t.Helper()
	s := &stubK8s{status: status, log: log}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/apis/batch/v1/namespaces/scanner-test/jobs", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.authSeen = append(s.authSeen, r.Header.Get("Authorization"))
		s.mu.Unlock()
		if r.Method == http.MethodPost {
			var body struct {
				Metadata struct{ Name string } `json:"metadata"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.mu.Lock()
			s.createdJobs = append(s.createdJobs, body.Metadata.Name)
			s.mu.Unlock()
			w.WriteHeader(201)
			w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(405)
	})
	mux.HandleFunc("/apis/batch/v1/namespaces/scanner-test/jobs/", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.authSeen = append(s.authSeen, r.Header.Get("Authorization"))
		s.mu.Unlock()
		name := strings.TrimPrefix(r.URL.Path, "/apis/batch/v1/namespaces/scanner-test/jobs/")
		switch r.Method {
		case http.MethodDelete:
			s.mu.Lock()
			s.deletedJobs = append(s.deletedJobs, name)
			s.mu.Unlock()
			w.WriteHeader(200)
		case http.MethodGet:
			s.mu.Lock()
			st := s.status
			s.mu.Unlock()
			out := map[string]any{
				"metadata": map[string]any{"name": name},
				"status":   map[string]any{},
			}
			switch st {
			case "succeeded":
				out["status"].(map[string]any)["succeeded"] = 1
			case "failed":
				out["status"].(map[string]any)["failed"] = 1
			}
			body, _ := json.Marshal(out)
			w.Write(body)
		}
	})
	mux.HandleFunc("/api/v1/namespaces/scanner-test/pods", func(w http.ResponseWriter, r *http.Request) {
		// label-selector lookup → return one pod.
		body, _ := json.Marshal(map[string]any{
			"items": []map[string]any{
				{"metadata": map[string]any{"name": "vs-tool-pod-abc"}},
			},
		})
		w.Write(body)
	})
	mux.HandleFunc("/api/v1/namespaces/scanner-test/pods/vs-tool-pod-abc/log", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		l := s.log
		s.mu.Unlock()
		w.Write([]byte(l))
	})

	r := &K8sJobRunner{
		cfg: K8sJobConfig{
			Namespace:      "scanner-test",
			ImageRegistry:  "registry.example/scanners",
			ServiceAccount: "scanner-tool",
		},
		token:      "stub-token",
		apiBase:    srv.URL,
		httpClient: srv.Client(),
	}
	return r, s
}

func TestK8sJobRunner_HappyPath(t *testing.T) {
	r, s := newStubK8s(t, "succeeded", "<nmaprun><host/></nmaprun>")
	res, err := r.Run(context.Background(), "nmap", []string{"127.0.0.1"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Output) != "<nmaprun><host/></nmaprun>" {
		t.Errorf("output mismatch: %q", res.Output)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d", res.ExitCode)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.createdJobs) != 1 {
		t.Errorf("expected 1 job created, got %d", len(s.createdJobs))
	}
	if len(s.deletedJobs) != 1 {
		t.Errorf("expected 1 job deleted, got %d", len(s.deletedJobs))
	}
	if !strings.HasPrefix(s.createdJobs[0], "vs-nmap-") {
		t.Errorf("job name not prefixed correctly: %q", s.createdJobs[0])
	}
}

func TestK8sJobRunner_FailedJobReturnsNonzero(t *testing.T) {
	r, _ := newStubK8s(t, "failed", "scanner ran out of memory")
	res, err := r.Run(context.Background(), "nuclei", []string{"x.example"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode == 0 {
		t.Error("expected non-zero exit code on failed job")
	}
}

func TestK8sJobRunner_SendsBearerAuth(t *testing.T) {
	r, s := newStubK8s(t, "succeeded", "")
	_, _ = r.Run(context.Background(), "nmap", []string{"x"}, 5*time.Second)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.authSeen) == 0 {
		t.Fatal("no auth header captured")
	}
	for _, h := range s.authSeen {
		if h != "Bearer stub-token" {
			t.Errorf("auth header %q != 'Bearer stub-token'", h)
		}
	}
}

func TestK8sJobRunner_JobNameIsDNS1123Safe(t *testing.T) {
	cases := []string{"nmap", "kube-bench", "test/ssl", "  weird  "}
	for _, c := range cases {
		n := jobNameFor(c)
		if len(n) > 50 {
			t.Errorf("jobNameFor(%q) too long: %s", c, n)
		}
		for _, r := range n {
			ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
			if !ok {
				t.Errorf("jobNameFor(%q) has illegal char %q in %q", c, r, n)
			}
		}
	}
}

func TestK8sJobRunner_ManifestSecurityContext(t *testing.T) {
	body := buildJobManifest("vs-test-x", "scanner-test", "scanner-tool",
		"registry/scanners/nmap:latest", "nmap",
		[]string{"-sV", "127.0.0.1"}, 30*time.Second)
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	spec := m["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	if spec["automountServiceAccountToken"] != false {
		t.Error("automountServiceAccountToken should be false (tool pods don't talk to K8s)")
	}
	sec := spec["securityContext"].(map[string]any)
	if sec["runAsNonRoot"] != true {
		t.Error("runAsNonRoot should be true")
	}
	cont := spec["containers"].([]any)[0].(map[string]any)
	contSec := cont["securityContext"].(map[string]any)
	if contSec["readOnlyRootFilesystem"] != true {
		t.Error("readOnlyRootFilesystem should be true on container")
	}
	if contSec["allowPrivilegeEscalation"] != false {
		t.Error("allowPrivilegeEscalation should be false")
	}
	caps := contSec["capabilities"].(map[string]any)
	drops := caps["drop"].([]any)
	if len(drops) != 1 || drops[0] != "ALL" {
		t.Errorf("expected capabilities.drop = [ALL], got %v", drops)
	}
	if backoff := m["spec"].(map[string]any)["backoffLimit"]; backoff != float64(0) {
		t.Errorf("backoffLimit should be 0, got %v", backoff)
	}
}

func TestK8sJobRunner_AllowsSyntheticAlwaysFalseByDefault(t *testing.T) {
	r, _ := newStubK8s(t, "succeeded", "")
	if r.AllowsSynthetic() {
		t.Error("K8sJobRunner.AllowsSynthetic should default false")
	}
}
