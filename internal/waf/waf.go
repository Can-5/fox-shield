// Package waf implements a lightweight Web Application Firewall with a set of
// regex signatures covering SQLi, XSS, RCE, path traversal, and other OWASP
// CRS-lite patterns. Each signature is compiled once at startup and matched
// with a short timeout to stay ReDoS-safe.
package waf

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/foxai/fox-shield/internal/ip"
	"github.com/foxai/fox-shield/internal/store"
)

// Signature is a single WAF rule.
type Signature struct {
	ID      string
	Category string
	Pattern *regexp.Regexp
}

// Rule is the declarative form used to build signatures.
type Rule struct {
	ID       string
	Category string
	Regex    string
}

// DefaultRules is the v1.0 signature set (20+ patterns).
var DefaultRules = []Rule{
	// SQL Injection
	{ID: "SQLI-001", Category: "sqli", Regex: `(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|delete\s+from|update\s+.*\s+set)`},
	{ID: "SQLI-002", Category: "sqli", Regex: `(?i)('|")\s*(or|and)\s*('|")\s*=\s*('|")`},
	{ID: "SQLI-003", Category: "sqli", Regex: `(?i)(--\s|#|/\*.*\*/)`},
	{ID: "SQLI-004", Category: "sqli", Regex: `(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep)`},
	{ID: "SQLI-005", Category: "sqli", Regex: `(?i)(information_schema|sys\.tables|mysql\.user|sqlite_master)`},
	{ID: "SQLI-006", Category: "sqli", Regex: `(?i)(0x[0-9a-f]{8,}|char\s*\(\s*\d+\s*\)|concat\s*\()`},
	// XSS
	{ID: "XSS-001", Category: "xss", Regex: `(?i)(<script|</script|javascript:|onerror\s*=|onload\s*=|onclick\s*=)`},
	{ID: "XSS-002", Category: "xss", Regex: `(?i)(<img[^>]*src|document\.cookie|alert\s*\(|eval\s*\()`},
	{ID: "XSS-003", Category: "xss", Regex: `(?i)(<iframe|<object|<embed|<svg[^>]*on)`},
	{ID: "XSS-004", Category: "xss", Regex: `(?i)(&#x[0-9a-f]{2,};|&#\d{2,};|%3c|%3e)`},
	// Remote Code Execution
	{ID: "RCE-001", Category: "rce", Regex: `(?i)(system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\(|popen\s*\()`},
	{ID: "RCE-002", Category: "rce", Regex: `(?i)(\$\{IFS\}|/bin/(sh|bash)|cmd\.exe|powershell\s+-)`},
	{ID: "RCE-003", Category: "rce", Regex: `(?i)(\|\s*(cat|nc|wget|curl|python|perl|php)\b|;\s*(cat|nc|wget|curl)\b)`},
	{ID: "RCE-004", Category: "rce", Regex: `(?i)(base64_decode\s*\(|eval\s*\(\s*\$|assert\s*\(\s*\$)`},
	{ID: "RCE-005", Category: "rce", Regex: `(?i)(\$\{jndi:|log4shell|log4j)`},
	// Path Traversal
	{ID: "TRAV-001", Category: "traversal", Regex: `(\.\./|\.\.\\|%2e%2e|%252e)`},
	{ID: "TRAV-002", Category: "traversal", Regex: `(?i)(/etc/passwd|/etc/shadow|/proc/self|/windows/win\.ini|/boot\.ini)`},
	{ID: "TRAV-003", Category: "traversal", Regex: `(?i)(file://|php://|data://|expect://|gopher://)`},
	// Other / OWASP CRS-lite
	{ID: "GEN-001", Category: "generic", Regex: `(?i)(<\%|%\>|<\?php|<\?xml)`},
	{ID: "GEN-002", Category: "generic", Regex: `(?i)(\x00|%00|\\x00)`},
	{ID: "GEN-003", Category: "generic", Regex: `(?i)(\.env|\.git/config|\.aws/credentials|id_rsa)`},
	{ID: "GEN-004", Category: "generic", Regex: `(?i)(\badmin\b.*\bpassword\b|root\s*:\s*\*|passwd\s*=\s*)`},
}

// WAF holds the compiled signature set.
type WAF struct {
	sigs    []Signature
	timeout time.Duration
	store   store.Store
}

// New compiles the given rules into a WAF. If rules is nil, DefaultRules is
// used. matchTimeout bounds each regex evaluation to stay ReDoS-safe.
func New(rules []Rule, matchTimeout time.Duration, s store.Store) (*WAF, error) {
	if rules == nil {
		rules = DefaultRules
	}
	if matchTimeout <= 0 {
		matchTimeout = 5 * time.Millisecond
	}
	w := &WAF{timeout: matchTimeout, store: s}
	for _, r := range rules {
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, err
		}
		w.sigs = append(w.sigs, Signature{ID: r.ID, Category: r.Category, Pattern: re})
	}
	return w, nil
}

// maxBodyBytes caps how much of the request body is scanned. Bodies larger
// than this cannot be fully inspected and are treated as suspicious rather
// than silently truncated (which would let a payload hide past the cap).
const maxBodyBytes = 1 << 20 // 1 MiB

// hopByHopHeaders are excluded from header scanning per RFC 7230 §6.1.
var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

// MatchResult describes the outcome of a WAF scan.
type MatchResult struct {
	ID       string
	Category string
	// OversizedBody is true when the request body exceeded the scan cap and
	// could not be fully inspected.
	OversizedBody bool
}

// Match scans the request target, headers and body for any signature. It
// returns the first matching signature ID and category, or an empty result if
// clean. OversizedBody is set when the body exceeded the scan cap.
func (w *WAF) Match(r *http.Request) MatchResult {
	target := r.Method + " " + r.URL.RequestURI()
	body, oversized := readBody(r)
	haystack := target + "\n" + headerHaystack(r) + "\n" + body

	for _, sig := range w.sigs {
		matched := matchWithTimeout(sig.Pattern, haystack, w.timeout)
		if matched {
			return MatchResult{ID: sig.ID, Category: sig.Category, OversizedBody: oversized}
		}
	}
	return MatchResult{OversizedBody: oversized}
}

// headerHaystack joins relevant request headers (lowercased name:value) into a
// single scan string so payloads smuggled in headers (User-Agent, Referer,
// X-*) are caught. Hop-by-hop headers are excluded.
func headerHaystack(r *http.Request) string {
	var b strings.Builder
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if _, skip := hopByHopHeaders[lower]; skip {
			continue
		}
		for _, v := range values {
			b.WriteString(lower)
			b.WriteByte(':')
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// Middleware wraps a handler. On a signature match or an oversized body it
// bans the client IP and returns 403. Hack attempts (any WAF signature) get unlimited ban.
func (w *WAF) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		res := w.Match(r)
		if res.ID != "" || res.OversizedBody {
			ipAddr := ip.ClientIP(r)
			reason := "waf:oversized-body"
			banDur := 60 * time.Minute
			if res.ID != "" {
				reason = "unlimited:waf:" + res.ID + ":" + res.Category
				banDur = 0
			}
			_ = store.BanReason(r.Context(), w.store, ipAddr, reason, banDur)
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			rw.WriteHeader(http.StatusForbidden)
			_, _ = rw.Write([]byte(`<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>you are banned ha ha ha</title><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0e14;color:#e5e7eb;font-family:system-ui} .card{background:#1f2937;border:1px solid #2d3748;border-radius:12px;padding:32px;max-width:560px;text-align:center} h1{color:#f6821f;font-size:32px} code{background:#0b0e14;padding:2px 6px;border-radius:4px;color:#f87171}</style></head><body><div class="card"><h1>you are banned ha ha ha 😂</h1><p>Sebep: <code>hacklemeye çalıştınız - ` + reason + `</code></p><p>fox-shield seni yakaladı</p></div></body></html>`))
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// matchWithTimeout runs a regex match under a deadline.
func matchWithTimeout(re *regexp.Regexp, s string, timeout time.Duration) bool {
	done := make(chan bool, 1)
	go func() {
		done <- re.MatchString(s)
	}()
	select {
	case res := <-done:
		return res
	case <-time.After(timeout):
		return false
	}
}

// readBody reads and restores the request body so downstream handlers can
// still read it. It returns the body string and whether it exceeded the scan
// cap (maxBodyBytes).
func readBody(r *http.Request) (string, bool) {
	if r.Body == nil {
		return "", false
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	oversized := false
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
		if len(buf) > maxBodyBytes {
			oversized = true
			break
		}
	}
	r.Body = newReplayBody(buf)
	return string(buf), oversized
}

// replayBody lets a consumed body be re-read.
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
