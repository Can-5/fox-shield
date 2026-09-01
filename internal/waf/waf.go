// Package waf implements a lightweight Web Application Firewall with a set of
// regex signatures covering SQLi, XSS, RCE, path traversal, and other OWASP
// CRS-lite patterns. Each signature is compiled once at startup and matched
// with a short timeout to stay ReDoS-safe.
package waf

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

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

// Match scans the request target and body for any signature. It returns the
// first matching signature ID and category, or ("", "") if clean.
func (w *WAF) Match(r *http.Request) (id, category string) {
	target := r.Method + " " + r.URL.RequestURI()
	body := readBody(r)
	haystack := target + "\n" + body

	for _, sig := range w.sigs {
		matched := matchWithTimeout(sig.Pattern, haystack, w.timeout)
		if matched {
			return sig.ID, sig.Category
		}
	}
	return "", ""
}

// Middleware wraps a handler. On a signature match it bans the client IP and
// returns 403.
func (w *WAF) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		id, cat := w.Match(r)
		if id != "" {
			ip := clientIP(r)
			_ = store.BanReason(r.Context(), w.store, ip, "waf:"+id+":"+cat, 60*time.Minute)
			http.Error(rw, "Forbidden", http.StatusForbidden)
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
// still read it.
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
		if len(buf) > 1<<20 { // cap at 1 MiB
			break
		}
	}
	r.Body = newReplayBody(buf)
	return string(buf)
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

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		return host[:i]
	}
	return host
}
