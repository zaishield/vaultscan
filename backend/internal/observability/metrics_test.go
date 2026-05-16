package observability

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPromHandlerExposesMetrics(t *testing.T) {
	t.Parallel()
	HTTPRequestsTotal.WithLabelValues("/api/v1/healthz", "GET", "200").Inc()
	srv := httptest.NewServer(PromHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "vaultscan_http_requests_total") {
		t.Fatalf("/metrics didn't include our counters:\n%s", body[:200])
	}
}

func TestRouteLabel_NormalisesIDs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"/api/v1/users/2c1b18f4-3a4f-4a8e-b7b3-1f9a9aa7d3a1/roles", "/api/v1/users/:id/roles"},
		{"/api/v1/scans/42", "/api/v1/scans/:id"},
		{"/api/v1/healthz", "/api/v1/healthz"},
		{"/static/img.png", "other"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", c.in, nil)
		if got := routeLabel(r); got != c.want {
			t.Errorf("routeLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHTTPDurationMiddleware_CountsRequests(t *testing.T) {
	t.Parallel()
	before := readCounter(t, "/api/v1/healthz", "GET", "200")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(HTTPDurationMiddleware(mux))
	defer srv.Close()
	for i := 0; i < 3; i++ {
		resp, err := http.Get(srv.URL + "/api/v1/healthz")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	after := readCounter(t, "/api/v1/healthz", "GET", "200")
	if after-before < 3 {
		t.Fatalf("expected counter delta >= 3, got %f", after-before)
	}
}

func readCounter(t *testing.T, route, method, status string) float64 {
	t.Helper()
	srv := httptest.NewServer(PromHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	wanted := `vaultscan_http_requests_total{method="` + method +
		`",route="` + route + `",status="` + status + `"}`
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, wanted) {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				return 0
			}
			f := 0.0
			for _, c := range parts[1] {
				if c >= '0' && c <= '9' {
					f = f*10 + float64(c-'0')
				}
			}
			return f
		}
	}
	return 0
}
