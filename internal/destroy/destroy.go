// Package destroy implements the final middleware in the shield chain. If a
// request was flagged as malicious by the WAF or similarity detector but was
// not banned for any reason, destroy drops it with a 403 "Destroyed" response
// and never forwards it to the origin. This guarantees malicious traffic
// cannot reach the origin even if an earlier ban failed.
package destroy

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/foxai/fox-shield/internal/ip"
)

// Destroyer is the final drop layer.
type Destroyer struct {
	destroyed atomic.Int64
}

// New creates a Destroyer.
func New() *Destroyer {
	return &Destroyer{}
}

// Destroyed returns the number of requests dropped by this layer.
func (d *Destroyer) Destroyed() int64 {
	return d.destroyed.Load()
}

// Middleware drops flagged requests. The request context carries a flag set by
// the WAF/similarity layers when they detect malicious content but choose not
// to ban (e.g. ban storage failed). If the flag is set, the request is
// destroyed here.
func (d *Destroyer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(ctxKeyMalicious) == true {
			d.destroyed.Add(1)
			log.Printf("destroy: dropped malicious request %s %s from %s", r.Method, r.URL.Path, ip.ClientIP(r))
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>you are banned ha ha ha</title><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0e14;color:#e5e7eb;font-family:system-ui} .card{background:#1f2937;border:1px solid #2d3748;border-radius:12px;padding:32px;max-width:560px;text-align:center} h1{color:#f6821f;font-size:32px}</style></head><body><div class="card"><h1>you are banned ha ha ha 😂</h1><p>Sebep: <code>hacklemeye çalıştınız — destroyed</code></p><p>fox-shield seni yakaladı</p></div></body></html>`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

type ctxKey int

const ctxKeyMalicious ctxKey = 0

// MarkMalicious returns a context flagging the request as malicious so the
// destroy layer drops it.
func MarkMalicious(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyMalicious, true)
}
