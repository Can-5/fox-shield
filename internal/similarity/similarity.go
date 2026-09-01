// Package similarity detects requests that closely resemble previously
// dark-listed malicious requests. Each request is normalized to a canonical
// string (method + path + sorted query keys + body hash), and a simple
// Levenshtein-based similarity score is computed against stored hashes. When
// the score exceeds the configured threshold the request is banned.
package similarity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/foxai/fox-shield/internal/ip"
	"github.com/foxai/fox-shield/internal/store"
)

// Config holds the similarity thresholds.
type Config struct {
	// Threshold is the similarity score (0..1) above which a request is
	// considered malicious in normal mode.
	Threshold float64
	// AggressiveThreshold is the threshold used in aggressive mode.
	AggressiveThreshold float64
	// BanDuration is how long a matched hash is dark-listed.
	BanDuration time.Duration
}

// DefaultConfig returns the v1.0 defaults from rules.toml.
func DefaultConfig() Config {
	return Config{
		Threshold:           0.90,
		AggressiveThreshold: 0.85,
		BanDuration:         60 * time.Minute,
	}
}

// Detector compares normalized requests against the dark list.
type Detector struct {
	cfg   Config
	store store.Store
}

// New creates a Detector.
func New(cfg Config, s store.Store) *Detector {
	return &Detector{cfg: cfg, store: s}
}

// Normalize produces a canonical string for a request.
func Normalize(r *http.Request) string {
	// Method + path.
	var sb strings.Builder
	sb.WriteString(r.Method)
	sb.WriteByte(' ')
	sb.WriteString(r.URL.Path)

	// Sorted query keys (values ignored to defeat trivial mutation).
	keys := make([]string, 0, len(r.URL.Query()))
	for k := range r.URL.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteByte('&')
		sb.WriteString(k)
	}

	// Body hash.
	body := readBody(r)
	sum := sha256.Sum256([]byte(body))
	sb.WriteByte('#')
	sb.WriteString(hex.EncodeToString(sum[:]))

	return sb.String()
}

// Hash returns the SHA-256 of a normalized request string.
func Hash(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

// Check evaluates a request against the dark list. It returns true if the
// request is malicious (similar to a stored dark hash) and bans the IP.
func (d *Detector) Check(ctx context.Context, r *http.Request, aggressive bool) bool {
	norm := Normalize(r)
	h := Hash(norm)

	// Exact dark-list hit is always malicious.
	if _, err := d.store.Get(ctx, store.DarkKey(h)); err == nil {
		return true
	}

	threshold := d.cfg.Threshold
	if aggressive {
		threshold = d.cfg.AggressiveThreshold
	}

	// Compare against a bounded sample of stored dark hashes. In a full
	// implementation this iterates the dark list from Redis/KV; here we check
	// the in-memory store's known keys via a lightweight scan.
	if d.scanDarkList(ctx, norm, threshold) {
		// Store the normalized request as the dark-list value so future
		// requests can be compared against it.
		_ = d.store.Set(ctx, store.DarkKey(h), norm, d.cfg.BanDuration)
		return true
	}
	return false
}

// scanDarkList compares the normalized request against stored dark hashes.
func (d *Detector) scanDarkList(ctx context.Context, norm string, threshold float64) bool {
	// The Store interface does not expose enumeration, so we rely on the
	// in-memory store's snapshot when available. This keeps the scaffold
	// dependency-free; a Redis-backed build would use SCAN.
	if ms, ok := d.store.(*store.MemoryStore); ok {
		for _, item := range ms.Snapshot() {
			if similarity(norm, item) >= threshold {
				return true
			}
		}
	}
	return false
}

// similarity returns a normalized Levenshtein-based similarity in [0,1].
func similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	dist := levenshtein(a, b)
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	return 1.0 - float64(dist)/float64(maxLen)
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

// Middleware wraps a handler, banning similar malicious requests. Similarity = hack variant → unlimited ban.
func (d *Detector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		aggressive := r.Context().Value(ctxKeyAggressive) == true
		if d.Check(r.Context(), r, aggressive) {
			ipAddr := ip.ClientIP(r)
			_ = store.BanReason(r.Context(), d.store, ipAddr, "unlimited:similarity-match", 0)
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			rw.WriteHeader(http.StatusForbidden)
			_, _ = rw.Write([]byte(`<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>you are banned ha ha ha</title><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0e14;color:#e5e7eb;font-family:system-ui} .card{background:#1f2937;border:1px solid #2d3748;border-radius:12px;padding:32px;max-width:560px;text-align:center} h1{color:#f6821f;font-size:32px}</style></head><body><div class="card"><h1>you are banned ha ha ha 😂</h1><p>Sebep: <code>hacklemeye çalıştınız — similarity</code></p><p>fox-shield seni yakaladı</p></div></body></html>`))
			return
		}
		next.ServeHTTP(rw, r)
	})
}

type ctxKey int

const ctxKeyAggressive ctxKey = 0

// WithAggressive returns a context carrying the aggressive-mode flag.
func WithAggressive(ctx context.Context, aggressive bool) context.Context {
	return context.WithValue(ctx, ctxKeyAggressive, aggressive)
}

func readBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
		if len(buf) > 1<<20 {
			break
		}
	}
	r.Body = newReplayBody(buf)
	return string(buf)
}

type replayBody struct {
	data []byte
	pos  int
}

func newReplayBody(data []byte) *replayBody { return &replayBody{data: data} }

func (b *replayBody) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

func (b *replayBody) Close() error { return nil }
