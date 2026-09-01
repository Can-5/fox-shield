// Package ip provides a spoof-resistant client IP extractor.
//
// The origin shield is normally deployed behind Cloudflare or a reverse proxy
// that sets CF-Connecting-IP / X-Forwarded-For. Those headers are attacker
// controllable when the origin is exposed directly, so by default we only
// trust the TCP peer address (RemoteAddr). Set TRUSTED_PROXY=1 in the
// environment to trust CF-Connecting-IP and X-Forwarded-For (only do this when
// the origin is guaranteed to sit behind a trusted proxy that overwrites these
// headers).
package ip

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash/fnv"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

var (
	trustedOnce sync.Once
	trusted     bool
	subnetOnce  sync.Once
	subnetLimit bool
)

// trustedProxy reports whether the process was configured to trust proxy
// headers via the TRUSTED_PROXY environment variable.
func trustedProxy() bool {
	trustedOnce.Do(func() {
		v := strings.TrimSpace(os.Getenv("TRUSTED_PROXY"))
		trusted = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	})
	return trusted
}

// subnetLimitEnabled reports whether IPv6 /64 subnet rate limiting is enabled
// via the SUBNET_LIMIT environment variable.
func subnetLimitEnabled() bool {
	subnetOnce.Do(func() {
		v := strings.TrimSpace(os.Getenv("SUBNET_LIMIT"))
		subnetLimit = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	})
	return subnetLimit
}

// ClientIP returns the spoof-resistant client IP for a request.
//
// When TRUSTED_PROXY=1 the CF-Connecting-IP header is preferred, then the
// first entry of X-Forwarded-For, then X-Real-IP, then the TCP peer address.
// Otherwise only the TCP peer address (RemoteAddr) is used, so an attacker
// cannot forge the value by sending arbitrary headers.
//
// The returned address is normalized (IPv6 zone stripped, lowercased) and,
// when SUBNET_LIMIT=1, IPv6 addresses are masked to their /64 subnet.
func ClientIP(r *http.Request) string {
	var raw string
	if trustedProxy() {
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
			raw = cf
		} else if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				raw = strings.TrimSpace(xff[:i])
			} else {
				raw = xff
			}
		} else if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
			raw = xr
		}
	}
	if raw == "" {
		raw = remoteHost(r.RemoteAddr)
	}
	return NormalizeIP(raw, subnetLimitEnabled())
}

// remoteHost strips the port from a RemoteAddr (host:port) value.
func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// RemoteAddr may already be host-only (e.g. some test clients).
		return remoteAddr
	}
	return host
}

// NormalizeIP canonicalizes an IP address for use as a rate-limit / ban key.
//
// It strips any IPv6 zone identifier (e.g. "fe80::1%eth0" -> "fe80::1"),
// lowercases the address, and — when subnetLimit is true — masks IPv6
// addresses to their /64 subnet so that an attacker rotating addresses within
// a single /64 (privacy addresses) is rate-limited as one unit. IPv4 addresses
// are returned unchanged.
//
// IP-based limits can be bypassed by rotating IPv6 addresses; enabling the
// /64 subnet limit (SUBNET_LIMIT=1) mitigates this at the cost of grouping
// legitimate hosts that share a /64.
func NormalizeIP(addr string, subnetLimit bool) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return addr
	}
	// Strip an IPv6 zone identifier ("%eth0").
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		addr = addr[:i]
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		// Not a parseable IP (e.g. a hostname); return lowercased as-is.
		return strings.ToLower(addr)
	}
	if ip.To4() != nil {
		return ip.String()
	}
	// IPv6: lowercase and optionally mask to the /64 subnet.
	ip = ip.To16()
	if subnetLimit {
		// Zero out the lower 64 bits to form the /64 prefix.
		for i := 8; i < 16; i++ {
			ip[i] = 0
		}
	}
	return ip.String()
}

// HashIP returns the HMAC-SHA256 hex digest of the raw IP under the given salt.
// It is used as the ban / offense key so a leaked store dump reveals nothing
// about who was banned. The raw IP is never stored as a key.
func HashIP(ip, salt string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(ip))
	return hex.EncodeToString(mac.Sum(nil))
}

// SubnetOf returns the canonical subnet prefix for an IP: IPv6 /64 (first 64
// bits), IPv4 /24 (first 24 bits). Returns "" for unparseable input.
func SubnetOf(addr string) string {
	addr = strings.TrimSpace(addr)
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		addr = addr[:i]
	}
	parsed := net.ParseIP(addr)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	v6 := parsed.To16()
	// Zero out the lower 64 bits to form the /64 prefix.
	for i := 8; i < 16; i++ {
		v6[i] = 0
	}
	return v6.String() + "/64"
}

// MaskIP returns a display-only masked form of the IP. It is never used as a
// key. IPv4 shows the first three octets (a.b.c.***); IPv6 keeps the /48 prefix
// (first three hextets) and masks the remaining five hextets.
func MaskIP(addr string) string {
	addr = strings.TrimSpace(addr)
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		addr = addr[:i]
	}
	parsed := net.ParseIP(addr)
	if parsed == nil {
		return "***.***.***.***"
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()[:len(v4.String())-1] + "***"
	}
	v6 := parsed.To16()
	groups := strings.Split(v6.String(), ":")
	if len(groups) >= 3 {
		return groups[0] + ":" + groups[1] + ":" + groups[2] + "::****:****:****:****"
	}
	return v6.String()
}

// DeviceHash returns a stable FNV-1a (32-bit) fingerprint over the request's
// ambient headers (User-Agent, Accept-Language, country, colo). It groups
// requests sharing the same browser/OS/language/region — the granularity wanted
// for a device ban — and never derives from a raw IP.
func DeviceHash(ua, acceptLang, country, colo string) string {
	h := fnv.New32a()
	h.Write([]byte(ua + "|" + acceptLang + "|" + country + "|" + colo))
	return hex.EncodeToString(h.Sum(nil))
}
