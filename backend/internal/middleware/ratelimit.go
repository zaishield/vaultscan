// ratelimit.go — pluggable rate-limit backends.
//
// The in-process token-bucket from middleware.go works for single-pod
// dev. Production (multiple API replicas) needs cross-pod state — a
// per-IP attacker would otherwise get N × ceiling RPS.
//
// Two backends ship in-tree:
//
//   InMemoryLimiter  — sync.Map of token buckets, no cross-pod
//                      coordination. Default for VAULTSCAN_ENV != prod.
//   RedisLimiter     — sliding-window counter against a single Redis
//                      (or Redis-compatible: DragonflyDB, KeyDB,
//                      Valkey, AWS ElastiCache, GCP Memorystore,
//                      Upstash). Atomic via Lua script.
//
// The RedisLimiter speaks the RESP wire protocol over a small in-house
// connection pool — no third-party deps in go.mod for a feature that's
// 80 lines of network code.

package middleware

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Limiter is the contract every backend implements.
type Limiter interface {
	// Allow returns true if a token is granted for `key` in the
	// rolling window of size `windowSec` against `limit`. ctx is
	// honored on backends that issue network calls.
	Allow(ctx context.Context, key string, limit, windowSec int) (bool, error)
	// Name surfaces the backend identifier in logs + /metrics.
	Name() string
}

// ---- In-memory token bucket -----------------------------------------------

type InMemoryLimiter struct {
	mu      sync.Mutex
	buckets map[string]*memBucket
}

type memBucket struct {
	tokens     float64
	lastRefill time.Time
}

func NewInMemoryLimiter() *InMemoryLimiter {
	return &InMemoryLimiter{buckets: map[string]*memBucket{}}
}

func (l *InMemoryLimiter) Name() string { return "memory" }

func (l *InMemoryLimiter) Allow(_ context.Context, key string, limit, windowSec int) (bool, error) {
	if windowSec <= 0 {
		windowSec = 1
	}
	rps := float64(limit) / float64(windowSec)
	burst := float64(limit) * 2
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		b = &memBucket{tokens: burst, lastRefill: now}
		l.buckets[key] = b
	}
	delta := now.Sub(b.lastRefill).Seconds()
	b.tokens = b.tokens + delta*rps
	if b.tokens > burst {
		b.tokens = burst
	}
	b.lastRefill = now
	if b.tokens < 1 {
		return false, nil
	}
	b.tokens--
	return true, nil
}

// ---- Redis sliding-window counter ----------------------------------------

// RedisLimiter implements a sliding-window rate limit using a sorted set.
// On each request:
//   1. Drop entries older than (now - windowSec) from the sorted set.
//   2. Count remaining entries → currentCount.
//   3. If currentCount < limit, ZADD a new entry, return true.
//
// All three steps are wrapped in a Lua EVAL so they're atomic.
type RedisLimiter struct {
	addr     string
	password string
	db       int
	dialTO   time.Duration
	pool     *redisPool
}

// NewRedisLimiter dials Redis at addr (host:port). password may be ""
// (no AUTH). Returns an error only on parse failure; the first real
// network error surfaces from Allow so the API can come up even if
// Redis is briefly unavailable at boot.
func NewRedisLimiter(addr, password string, db int) (*RedisLimiter, error) {
	if addr == "" {
		return nil, errors.New("rate-limit: redis addr required")
	}
	rl := &RedisLimiter{
		addr:     addr,
		password: password,
		db:       db,
		dialTO:   3 * time.Second,
	}
	rl.pool = newRedisPool(rl.dial, 16)
	return rl, nil
}

func (rl *RedisLimiter) Name() string { return "redis" }

const slidingWindowLua = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call("ZREMRANGEBYSCORE", key, "-inf", now - window)
local count = redis.call("ZCARD", key)
if count >= limit then
  return 0
end
redis.call("ZADD", key, now, member)
redis.call("EXPIRE", key, window + 1)
return 1
`

func (rl *RedisLimiter) Allow(ctx context.Context, key string, limit, windowSec int) (bool, error) {
	if limit <= 0 {
		return true, nil
	}
	now := time.Now().Unix()
	member := fmt.Sprintf("%d-%s", now, randomToken(8))
	conn, err := rl.pool.get(ctx)
	if err != nil {
		return false, err
	}
	defer rl.pool.put(conn)
	args := []string{
		"EVAL", slidingWindowLua, "1", "ratelimit:" + key,
		strconv.FormatInt(now, 10), strconv.Itoa(windowSec),
		strconv.Itoa(limit), member,
	}
	resp, err := conn.do(ctx, args...)
	if err != nil {
		return false, err
	}
	allowed, _ := resp.(int64)
	return allowed == 1, nil
}

// ---- minimal RESP client + connection pool -------------------------------

type redisConn struct {
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer
}

func (rl *RedisLimiter) dial(ctx context.Context) (*redisConn, error) {
	d := net.Dialer{Timeout: rl.dialTO}
	c, err := d.DialContext(ctx, "tcp", rl.addr)
	if err != nil {
		return nil, err
	}
	rc := &redisConn{conn: c, br: bufio.NewReader(c), bw: bufio.NewWriter(c)}
	if rl.password != "" {
		if _, err := rc.do(ctx, "AUTH", rl.password); err != nil {
			c.Close()
			return nil, err
		}
	}
	if rl.db != 0 {
		if _, err := rc.do(ctx, "SELECT", strconv.Itoa(rl.db)); err != nil {
			c.Close()
			return nil, err
		}
	}
	return rc, nil
}

func (c *redisConn) close() { _ = c.conn.Close() }

func (c *redisConn) do(ctx context.Context, args ...string) (any, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(dl)
	} else {
		_ = c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	// Inline command serialization (RESP2).
	fmt.Fprintf(c.bw, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(c.bw, "$%d\r\n%s\r\n", len(a), a)
	}
	if err := c.bw.Flush(); err != nil {
		return nil, err
	}
	return readReply(c.br)
}

func readReply(br *bufio.Reader) (any, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, errors.New("redis: empty reply")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, errors.New("redis: " + line[1:])
	case ':':
		return strconv.ParseInt(line[1:], 10, 64)
	case '$':
		size, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		if size < 0 {
			return nil, nil
		}
		buf := make([]byte, size+2)
		if _, err := br.Read(buf); err != nil {
			return nil, err
		}
		return string(buf[:size]), nil
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		out := make([]any, n)
		for i := 0; i < n; i++ {
			out[i], err = readReply(br)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("redis: unknown reply prefix %q", line[0])
}

// redisPool is a tiny channel-backed conn pool.
type redisPool struct {
	dial func(ctx context.Context) (*redisConn, error)
	cap  int
	idle chan *redisConn
}

func newRedisPool(dial func(ctx context.Context) (*redisConn, error), cap int) *redisPool {
	return &redisPool{dial: dial, cap: cap, idle: make(chan *redisConn, cap)}
}

func (p *redisPool) get(ctx context.Context) (*redisConn, error) {
	select {
	case c := <-p.idle:
		return c, nil
	default:
		return p.dial(ctx)
	}
}

func (p *redisPool) put(c *redisConn) {
	select {
	case p.idle <- c:
	default:
		c.close()
	}
}

// randomToken returns n hex chars from time-based xorshift. Good enough
// for sorted-set member uniqueness inside a 1-second window.
func randomToken(n int) string {
	const hex = "0123456789abcdef"
	x := uint64(time.Now().UnixNano())
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out[i] = hex[int(x)&15]
	}
	return string(out)
}

// ---- Middleware that uses a Limiter --------------------------------------

// RateLimitMiddleware wraps a Limiter so it can be plugged into chi.
// limit + window can be set per-deploy; defaults to 100 req / 60 s.
type RateLimitMiddleware struct {
	limiter Limiter
	limit   int
	window  int
}

func NewRateLimitMiddleware(l Limiter, limit, windowSec int) *RateLimitMiddleware {
	if limit <= 0 {
		limit = 100
	}
	if windowSec <= 0 {
		windowSec = 60
	}
	return &RateLimitMiddleware{limiter: l, limit: limit, window: windowSec}
}

func (m *RateLimitMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := identityKey(r)
		ok, err := m.limiter.Allow(r.Context(), key, m.limit, m.window)
		if err != nil {
			// Fail open on backend failure — better to serve traffic
			// than 503 the whole API when Redis is briefly down. Log
			// the error from the calling site if you want it surfaced.
			next.ServeHTTP(w, r)
			return
		}
		if !ok {
			writeJSONError(w, 429, "rate_limited", "slow down")
			return
		}
		next.ServeHTTP(w, r)
	})
}
