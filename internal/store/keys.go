package store

import (
	"context"
	"time"
)

// Key helpers centralize the shared key schema so the origin shield and the
// edge worker use identical names.

// RateLimitKey returns the sliding-window counter key for an IP.
func RateLimitKey(ip string) string { return "ratelimit:" + ip }

// BanKey returns the ban key for an IP.
func BanKey(ip string) string { return "ban:" + ip }

// DarkKey returns the dark-list hash key.
func DarkKey(hash string) string { return "dark:" + hash }

// BanReason is a convenience wrapper that records a ban with a reason and TTL.
func BanReason(ctx context.Context, s Store, ip, reason string, ttl time.Duration) error {
	return s.Set(ctx, BanKey(ip), reason, ttl)
}

// IsBanned reports whether an IP is currently banned.
func IsBanned(ctx context.Context, s Store, ip string) (bool, error) {
	_, err := s.Get(ctx, BanKey(ip))
	if err == ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
