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
			http.Error(w, "Destroyed", http.StatusForbidden)
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
