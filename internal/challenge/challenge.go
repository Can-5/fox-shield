// Package challenge implements a JavaScript proof-of-work challenge. The
// shield serves a challenge page at /__shield/challenge that generates a
// random nonce; the client must find a value whose SHA-256 hash starts with a
// configurable number of leading zero bits. On success a __shield_pass cookie
// is set and the client is allowed through.
//
// Security: the pass cookie value is a random 32-byte token stored in the
// store with a TTL, so a static or guessed cookie is rejected. The proof nonce
// is bound to the client IP and timestamp, stored server-side, and deleted
// after a single use to prevent replay and fixation. The CAPTCHA answer is
// stored server-side keyed by the nonce rather than embedded in the HTML.
package challenge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/foxai/fox-shield/internal/ip"
	"github.com/foxai/fox-shield/internal/limiter"
	"github.com/foxai/fox-shield/internal/store"
)

// Config holds challenge parameters.
type Config struct {
	// DifficultyNormal is the number of leading zero bits required in normal
	// mode.
	DifficultyNormal int
	// DifficultyAggressive is the difficulty in aggressive mode.
	DifficultyAggressive int
	// PassTTL is how long a solved __shield_pass cookie is valid.
	PassTTL time.Duration
	// NonceTTL is how long a proof-of-work nonce remains valid.
	NonceTTL time.Duration
}

// DefaultConfig returns the v1.0 defaults.
func DefaultConfig() Config {
	return Config{
		DifficultyNormal:     4,
		DifficultyAggressive: 5,
		PassTTL:              10 * time.Minute,
		NonceTTL:             2 * time.Minute,
	}
}

// CookieName is the name of the proof-of-work pass cookie.
const CookieName = "__shield_pass"

// Challenge issues and verifies proof-of-work challenges.
type Challenge struct {
	cfg   Config
	store store.Store
}

// New creates a Challenge.
func New(cfg Config, s store.Store) *Challenge {
	return &Challenge{cfg: cfg, store: s}
}

// passKey returns the store key for a pass token.
func passKey(token string) string { return "pass:" + token }

// nonceKey returns the store key for a proof nonce.
func nonceKey(nonce string) string { return "nonce:" + nonce }

// Handler serves the challenge endpoint. It returns a JSON payload with the
// nonce and difficulty, and verifies submitted solutions.
func (c *Challenge) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			c.verify(w, r)
			return
		}
		nonce := randomHex(16)
		difficulty := c.cfg.DifficultyNormal
		if r.Context().Value(ctxKeyAggressive) == true {
			difficulty = c.cfg.DifficultyAggressive
		}
		// Bind the nonce to the client IP and a timestamp, stored server-side.
		clientIP := ip.ClientIP(r)
		_ = c.store.Set(r.Context(), nonceKey(nonce), clientIP, c.cfg.NonceTTL)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"nonce":      nonce,
			"difficulty": difficulty,
			"algorithm":  "sha256",
		})
	})
}

func (c *Challenge) verify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Nonce string `json:"nonce"`
		Proof string `json:"proof"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	difficulty := c.cfg.DifficultyNormal
	if r.Context().Value(ctxKeyAggressive) == true {
		difficulty = c.cfg.DifficultyAggressive
	}
	if !c.validProof(r.Context(), req.Nonce, req.Proof, difficulty, ip.ClientIP(r)) {
		http.Error(w, "Invalid Proof", http.StatusForbidden)
		return
	}
	c.issuePass(w, r)
}

// validProof checks that the nonce was issued for this client IP and that
// sha256(nonce+proof) has `difficulty` leading zero bits. The nonce is
// one-time: it is deleted after verification to prevent replay.
func (c *Challenge) validProof(ctx context.Context, nonce, proof string, difficulty int, clientIP string) bool {
	if nonce == "" || proof == "" {
		return false
	}
	// The nonce must exist and be bound to the requesting IP.
	boundIP, err := c.store.Get(ctx, nonceKey(nonce))
	if err != nil {
		return false
	}
	// Delete the nonce immediately (one-time use) regardless of proof result.
	_ = c.store.Delete(ctx, nonceKey(nonce))
	if boundIP != clientIP {
		return false
	}
	sum := sha256.Sum256([]byte(nonce + proof))
	hexStr := hex.EncodeToString(sum[:])
	bits := 0
	for i := 0; i < len(hexStr); i++ {
		v := hexVal(hexStr[i])
		if v == 0 {
			bits += 4
			continue
		}
		for shift := 3; shift >= 0; shift-- {
			if v&(1<<shift) == 0 {
				bits++
			} else {
				break
			}
		}
		break
	}
	return bits >= difficulty
}

// issuePass issues a random pass token, stores it with a TTL, and sets it as
// the __shield_pass cookie.
func (c *Challenge) issuePass(w http.ResponseWriter, r *http.Request) {
	token := randomHex(32)
	_ = c.store.Set(r.Context(), passKey(token), ip.ClientIP(r), c.cfg.PassTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(c.cfg.PassTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return 0
}

// Middleware requires a valid pass cookie for suspicious requests, otherwise
// it serves the challenge. Requests not marked suspicious pass through.
func (c *Challenge) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/__shield/") {
			next.ServeHTTP(w, r)
			return
		}
		if !limiter.IsSuspicious(r.Context()) {
			next.ServeHTTP(w, r)
			return
		}
		if c.hasValidPass(r) {
			next.ServeHTTP(w, r)
			return
		}
		c.Handler().ServeHTTP(w, r)
	})
}

// hasValidPass reports whether the request carries a pass cookie whose token
// exists in the store (i.e. was actually issued by this shield).
func (c *Challenge) hasValidPass(r *http.Request) bool {
	cookie, err := r.Cookie(CookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	boundIP, err := c.store.Get(r.Context(), passKey(cookie.Value))
	if err != nil {
		return false
	}
	return boundIP == ip.ClientIP(r)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}

type ctxKey int

const ctxKeyAggressive ctxKey = 0

// WithAggressive returns a context carrying the aggressive-mode flag.
func WithAggressive(ctx context.Context, aggressive bool) context.Context {
	return context.WithValue(ctx, ctxKeyAggressive, aggressive)
}
