package ip

import (
	"net/http"
	"os"
	"sync"
	"testing"
)

// resetEnv clears the cached TRUSTED_PROXY / SUBNET_LIMIT flags so each test
// observes the environment it sets.
func resetEnv(t *testing.T) {
	t.Helper()
	trusted = false
	subnetLimit = false
	trustedOnce = sync.Once{}
	subnetOnce = sync.Once{}
	t.Cleanup(func() {
		_ = os.Unsetenv("TRUSTED_PROXY")
		_ = os.Unsetenv("SUBNET_LIMIT")
		trusted = false
		subnetLimit = false
		trustedOnce = sync.Once{}
		subnetOnce = sync.Once{}
	})
}

func TestClientIPIgnoresSpoofedXFFWhenProxyUntrusted(t *testing.T) {
	resetEnv(t)
	_ = os.Unsetenv("TRUSTED_PROXY")

	r := &http.Request{
		RemoteAddr: "203.0.113.9:54321",
		Header:     http.Header{},
	}
	r.Header.Set("X-Forwarded-For", "6.6.6.6")
	r.Header.Set("CF-Connecting-IP", "7.7.7.7")
	got := ClientIP(r)
	if got != "203.0.113.9" {
		t.Fatalf("ClientIP with TRUSTED_PROXY unset = %q, want RemoteAddr 203.0.113.9 (spoofed XFF must not bypass)", got)
	}
}

func TestClientIPTrustsProxyWhenEnabled(t *testing.T) {
	resetEnv(t)
	_ = os.Setenv("TRUSTED_PROXY", "1")

	r := &http.Request{
		RemoteAddr: "203.0.113.9:54321",
		Header:     http.Header{},
	}
	r.Header.Set("CF-Connecting-IP", "7.7.7.7")
	got := ClientIP(r)
	if got != "7.7.7.7" {
		t.Fatalf("ClientIP with TRUSTED_PROXY=1 = %q, want CF-Connecting-IP 7.7.7.7", got)
	}
}

func TestNormalizeIPStripsZoneAndLowercases(t *testing.T) {
	got := NormalizeIP("FE80::1%eth0", false)
	if got != "fe80::1" {
		t.Fatalf("NormalizeIP(zone) = %q, want fe80::1", got)
	}
}

func TestNormalizeIPSubnet64(t *testing.T) {
	got := NormalizeIP("2001:db8:abcd:0012:1111:2222:3333:4444", true)
	if got != "2001:db8:abcd:12::" {
		t.Fatalf("NormalizeIP(/64) = %q, want 2001:db8:abcd:12::", got)
	}
}

func TestNormalizeIPLeavesIPv4(t *testing.T) {
	got := NormalizeIP("203.0.113.9", true)
	if got != "203.0.113.9" {
		t.Fatalf("NormalizeIP(ipv4) = %q, want 203.0.113.9", got)
	}
}
