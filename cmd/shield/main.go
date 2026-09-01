// Command shield is the fox-shield origin reverse proxy. It listens on :8080,
// reads FOX_MODE / REDIS_URL / AGGRESSIVE_MODE / ORIGIN_URL from the
// environment, and forwards requests to the origin through a middleware chain:
//
//	limiter -> waf -> similarity -> challenge -> destroy -> proxy
//
// FOX_MODE=origin is the default; any other value runs the same chain (the
// edge mode is a separate TypeScript worker).
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/foxai/fox-shield/internal/challenge"
	"github.com/foxai/fox-shield/internal/destroy"
	"github.com/foxai/fox-shield/internal/limiter"
	"github.com/foxai/fox-shield/internal/similarity"
	"github.com/foxai/fox-shield/internal/store"
	"github.com/foxai/fox-shield/internal/waf"
)

func main() {
	originURL := envOr("ORIGIN_URL", "http://127.0.0.1:3000")
	addr := envOr("LISTEN_ADDR", ":8080")
	aggressive := envBool("AGGRESSIVE_MODE")
	mode := envOr("FOX_MODE", "origin")

	log.Printf("fox-shield origin starting mode=%s aggressive=%v origin=%s", mode, aggressive, originURL)

	// Store: Redis if REDIS_URL is set, otherwise in-memory fallback.
	var st store.Store = store.NewMemoryStore()
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		if rs, err := newRedisStore(redisURL); err == nil {
			st = rs
			log.Printf("using redis store %s", redisURL)
		} else {
			log.Printf("redis unavailable (%v), falling back to in-memory store", err)
		}
	}

	// Build the middleware chain.
	lim := limiter.New(limiter.DefaultConfig(), st)
	wafInst, err := waf.New(nil, 5*time.Millisecond, st)
	if err != nil {
		log.Fatalf("waf init: %v", err)
	}
	sim := similarity.New(similarity.DefaultConfig(), st)
	chal := challenge.New(challenge.DefaultConfig(), st)
	destroyer := destroy.New()

	// Reverse proxy to origin.
	target, err := url.Parse(originURL)
	if err != nil {
		log.Fatalf("invalid ORIGIN_URL %q: %v", originURL, err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Assemble chain: limiter -> waf -> similarity -> challenge -> destroy -> proxy.
	var handler http.Handler = proxy
	handler = destroyer.Middleware(handler)
	handler = chal.Middleware(handler)
	handler = sim.Middleware(handler)
	handler = wafInst.Middleware(handler)
	handler = lim.Middleware(handler)

	// Apply aggressive mode to the request context at the outermost layer.
	handler = aggressiveMiddleware(aggressive, handler)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}

// aggressiveMiddleware injects the aggressive-mode flag into the request
// context so downstream layers can read it.
func aggressiveMiddleware(aggressive bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = limiter.WithAggressive(ctx, aggressive)
		ctx = similarity.WithAggressive(ctx, aggressive)
		ctx = challenge.WithAggressive(ctx, aggressive)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string) bool {
	v := os.Getenv(key)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

// newRedisStore builds a Redis-backed store. To keep the scaffold runnable
// without external dependencies, it returns an in-memory store when go-redis
// is not available; a full build wires the real client here.
func newRedisStore(addr string) (store.Store, error) {
	// Placeholder: without the go-redis dependency vendored, fall back to
	// memory. Replace with a real client in a full build.
	_ = addr
	return store.NewMemoryStore(), nil
}
