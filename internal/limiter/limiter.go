// Package limiter implements a token-bucket sliding-window rate limiter.
//
// Each IP gets a token bucket that refills at `rps` tokens per second up to a
// `burst` capacity. A sliding window (window_ms) is layered on top so that a
// burst cannot exceed the per-second budget. When the limit is exceeded the
// limiter returns a 429 with a Retry-After header and, after repeated
// violations, bans the IP for a configurable duration.
package limiter

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/foxai/fox-shield/internal/store"
)

// Config holds the tunable rate-limit parameters.
type Config struct {
	// NormalRPS is the per-IP request budget in normal mode.
	NormalRPS int
	// AggressiveRPS is the per-IP request budget in aggressive mode.
	AggressiveRPS int
	// Burst is the token bucket capacity in normal mode.
	Burst int
	// AggressiveBurst is the token bucket capacity in aggressive mode.
	AggressiveBurst int
	// WindowMS is the sliding window length in milliseconds.
	WindowMS int
	// BanNormal is how long an IP is banned after exceeding normal limits.
	BanNormal time.Duration
	// BanAggressive is how long an IP is banned in aggressive mode.
	BanAggressive time.Duration
	// ViolationsBeforeBan is how many limit violations trigger a ban.
	ViolationsBeforeBan int
}

// DefaultConfig returns the v1.0 defaults from rules.toml.
func DefaultConfig() Config {
	return Config{
		NormalRPS:           20,
		AggressiveRPS:       10,
		Burst:               40,
		AggressiveBurst:     20,
		WindowMS:            1000,
		BanNormal:           10 * time.Minute,
		BanAggressive:       60 * time.Minute,
		ViolationsBeforeBan: 3,
	}
}

// Limiter enforces per-IP rate limits.
type Limiter struct {
	cfg    Config
	store  store.Store
	mu     sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens   float64
	last     time.Time
	violations int
}

// New creates a Limiter backed by the given store.
func New(cfg Config, s store.Store) *Limiter {
	return &Limiter{cfg: cfg, store: s, buckets: make(map[string]*bucket)}
}

// Allow reports whether the request from ip is within budget. If it returns
// false, retryAfter is the number of seconds the client should wait. The
// suspicious return value is true when the IP is near the limit (>=80% of
// burst consumed), which downstream layers use to trigger a challenge.
func (l *Limiter) Allow(ctx context.Context, ip string, aggressive bool) (ok bool, retryAfter int, suspicious bool) {
	rps := l.cfg.NormalRPS
	burst := l.cfg.Burst
	ban := l.cfg.BanNormal
	if aggressive {
		rps = l.cfg.AggressiveRPS
		burst = l.cfg.AggressiveBurst
		ban = l.cfg.BanAggressive
	}

	now := time.Now()
	l.mu.Lock()
	b, exists := l.buckets[ip]
	if !exists {
		b = &bucket{tokens: float64(burst), last: now}
		l.buckets[ip] = b
	}
	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * float64(rps)
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		b.violations = 0
		// Suspicious when more than 80% of burst is consumed.
		suspicious = b.tokens <= float64(burst)*0.2
		l.mu.Unlock()
		return true, 0, suspicious
	}

	// Over budget: record a violation and possibly ban.
	b.violations++
	viol := b.violations
	l.mu.Unlock()

	// Retry-After in seconds: one token refills every 1/rps seconds.
	retryAfter = int(1.0 / float64(rps))
	if retryAfter < 1 {
		retryAfter = 1
	}

	if viol >= l.cfg.ViolationsBeforeBan {
		_ = store.BanReason(ctx, l.store, ip, "rate-limit exceeded", ban)
	}

	return false, retryAfter, true
}

// Middleware wraps an http.Handler with rate limiting. It returns 429 with a
// Retry-After header when the limit is exceeded, and marks near-limit requests
// as suspicious so downstream challenge middleware can require proof of work.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		aggressive := r.Context().Value(ctxKeyAggressive) == true
		ok, retryAfter, suspicious := l.Allow(r.Context(), ip, aggressive)
		if !ok {
			w.Header().Set("Retry-After", itoa(retryAfter))
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		ctx := r.Context()
		if suspicious {
			ctx = MarkSuspicious(ctx)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type ctxKey int

const ctxKeyAggressive ctxKey = 0

const ctxKeySuspicious ctxKey = 1

// WithAggressive returns a context carrying the aggressive-mode flag.
func WithAggressive(ctx context.Context, aggressive bool) context.Context {
	return context.WithValue(ctx, ctxKeyAggressive, aggressive)
}

// MarkSuspicious returns a context flagging the request as suspicious.
func MarkSuspicious(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeySuspicious, true)
}

// IsSuspicious reports whether the request was flagged as suspicious.
func IsSuspicious(ctx context.Context) bool {
	return ctx.Value(ctxKeySuspicious) == true
}

// ClientIP extracts the client IP from the request, honoring the
// X-Forwarded-For header set by Cloudflare or a reverse proxy.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return trimSpace(xff[:i])
			}
		}
		return trimSpace(xff)
	}
	if ra := r.Header.Get("X-Real-IP"); ra != "" {
		return trimSpace(ra)
	}
	host := r.RemoteAddr
	for i := 0; i < len(host); i++ {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
