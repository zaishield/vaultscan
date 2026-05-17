package middleware

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestInMemoryLimiter_Basic(t *testing.T) {
	t.Parallel()
	l := NewInMemoryLimiter()
	ctx := context.Background()
	allowed := 0
	for i := 0; i < 200; i++ {
		ok, _ := l.Allow(ctx, "k", 100, 1)
		if ok {
			allowed++
		}
	}
	// Burst is limit*2 (200), and rps is 100/1 = 100, so the first
	// burst should let through ~200 requests instantaneously.
	if allowed < 100 || allowed > 220 {
		t.Errorf("allowed=%d, want ~100-220", allowed)
	}
}

func TestInMemoryLimiter_RefillOverTime(t *testing.T) {
	t.Parallel()
	l := NewInMemoryLimiter()
	ctx := context.Background()
	for i := 0; i < 1000; i++ {
		_, _ = l.Allow(ctx, "k", 5, 1)
	}
	// Drained. After waiting 1s, should refill.
	time.Sleep(1100 * time.Millisecond)
	ok, _ := l.Allow(ctx, "k", 5, 1)
	if !ok {
		t.Error("expected refill after wait")
	}
}

func TestInMemoryLimiter_KeysAreIsolated(t *testing.T) {
	t.Parallel()
	l := NewInMemoryLimiter()
	ctx := context.Background()
	for i := 0; i < 1000; i++ {
		_, _ = l.Allow(ctx, "alice", 1, 60)
	}
	// Alice is rate-limited; Bob is fresh.
	if ok, _ := l.Allow(ctx, "bob", 1, 60); !ok {
		t.Error("Bob's quota shouldn't be affected by Alice")
	}
}

// stubRedisServer accepts RESP requests + canned-replies. Captures
// commands so the test can assert what the limiter sent.
type stubRedis struct {
	t           *testing.T
	listener    net.Listener
	mu          sync.Mutex
	allowedNext bool
	commands    [][]string
}

func newStubRedis(t *testing.T) *stubRedis {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &stubRedis{t: t, listener: l, allowedNext: true}
	go s.serve()
	return s
}

func (s *stubRedis) addr() string { return s.listener.Addr().String() }

func (s *stubRedis) close() { s.listener.Close() }

func (s *stubRedis) serve() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *stubRedis) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)
	for {
		args, err := readArrayCommand(br)
		if err != nil {
			return
		}
		s.mu.Lock()
		s.commands = append(s.commands, args)
		allow := s.allowedNext
		s.mu.Unlock()
		// EVAL → integer reply (1 if allowed, 0 if not).
		// AUTH/SELECT → simple OK.
		switch strings.ToUpper(args[0]) {
		case "AUTH", "SELECT":
			fmt.Fprintf(bw, "+OK\r\n")
		case "EVAL":
			v := 0
			if allow {
				v = 1
			}
			fmt.Fprintf(bw, ":%d\r\n", v)
		default:
			fmt.Fprintf(bw, "-ERR unknown\r\n")
		}
		_ = bw.Flush()
	}
}

func readArrayCommand(br *bufio.Reader) ([]string, error) {
	header, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	header = strings.TrimRight(header, "\r\n")
	if len(header) == 0 || header[0] != '*' {
		return nil, errors.New("not array")
	}
	n, _ := strconv.Atoi(header[1:])
	out := make([]string, n)
	for i := 0; i < n; i++ {
		szLine, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		szLine = strings.TrimRight(szLine, "\r\n")
		sz, _ := strconv.Atoi(szLine[1:])
		buf := make([]byte, sz+2)
		if _, err := br.Read(buf); err != nil {
			return nil, err
		}
		out[i] = string(buf[:sz])
	}
	return out, nil
}

func TestRedisLimiter_AllowsThenBlocks(t *testing.T) {
	t.Parallel()
	stub := newStubRedis(t)
	defer stub.close()

	rl, err := NewRedisLimiter(stub.addr(), "", 0)
	if err != nil {
		t.Fatal(err)
	}

	stub.mu.Lock()
	stub.allowedNext = true
	stub.mu.Unlock()
	ok, err := rl.Allow(context.Background(), "k", 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected allow")
	}

	stub.mu.Lock()
	stub.allowedNext = false
	stub.mu.Unlock()
	ok, _ = rl.Allow(context.Background(), "k", 10, 1)
	if ok {
		t.Error("expected block")
	}
}

func TestRedisLimiter_AuthHandshake(t *testing.T) {
	t.Parallel()
	stub := newStubRedis(t)
	defer stub.close()

	rl, _ := NewRedisLimiter(stub.addr(), "secret-pw", 2)
	_, _ = rl.Allow(context.Background(), "k", 1, 1)

	stub.mu.Lock()
	defer stub.mu.Unlock()
	hasAuth := false
	hasSelect := false
	for _, cmd := range stub.commands {
		if len(cmd) >= 2 && strings.ToUpper(cmd[0]) == "AUTH" && cmd[1] == "secret-pw" {
			hasAuth = true
		}
		if len(cmd) >= 2 && strings.ToUpper(cmd[0]) == "SELECT" && cmd[1] == "2" {
			hasSelect = true
		}
	}
	if !hasAuth {
		t.Error("AUTH not sent")
	}
	if !hasSelect {
		t.Error("SELECT 2 not sent")
	}
}

func TestNewRedisLimiter_RejectsEmptyAddr(t *testing.T) {
	t.Parallel()
	if _, err := NewRedisLimiter("", "", 0); err == nil {
		t.Error("expected error on empty addr")
	}
}

// Default = fail closed. When the backend errors, the middleware
// returns 503 + Retry-After. This closes the DoS vector where an
// attacker drops Redis to remove rate limits.
func TestRateLimitMiddleware_FailClosedOnBackendError(t *testing.T) {
	t.Parallel()
	mid := NewRateLimitMiddleware(brokenLimiter{}, 1, 1)
	called := false
	srv := httptest.NewServer(mid.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})))
	defer srv.Close()
	resp, _ := http.Get(srv.URL)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (fail closed), got %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 503")
	}
	if called {
		t.Error("handler should NOT be called when limiter errors and fail-open is off")
	}
}

// Opt-in fail open. Some deploys prefer availability over the
// brief unprotected window during a Redis blip.
func TestRateLimitMiddleware_FailOpenWhenEnabled(t *testing.T) {
	t.Parallel()
	mid := NewRateLimitMiddleware(brokenLimiter{}, 1, 1)
	mid.SetFailOpen(true)
	called := false
	srv := httptest.NewServer(mid.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})))
	defer srv.Close()
	resp, _ := http.Get(srv.URL)
	if resp.StatusCode != 200 {
		t.Errorf("expected 200 (fail open), got %d", resp.StatusCode)
	}
	if !called {
		t.Error("handler not called when fail-open is on")
	}
	if resp.Header.Get("X-RateLimit-Backend") != "degraded" {
		t.Error("expected X-RateLimit-Backend: degraded header on fail-open")
	}
}

type brokenLimiter struct{}

func (brokenLimiter) Name() string { return "broken" }
func (brokenLimiter) Allow(_ context.Context, _ string, _, _ int) (bool, error) {
	return false, errors.New("broken")
}

func TestRateLimitMiddleware_429WhenBlocked(t *testing.T) {
	t.Parallel()
	// Limiter that always denies → middleware should 429.
	mid := NewRateLimitMiddleware(denyLimiter{}, 1, 1)
	srv := httptest.NewServer(mid.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when blocked")
	})))
	defer srv.Close()
	resp, _ := http.Get(srv.URL)
	if resp.StatusCode != 429 {
		t.Errorf("expected 429, got %d", resp.StatusCode)
	}
}

type denyLimiter struct{}

func (denyLimiter) Name() string { return "deny" }
func (denyLimiter) Allow(_ context.Context, _ string, _, _ int) (bool, error) {
	return false, nil
}
