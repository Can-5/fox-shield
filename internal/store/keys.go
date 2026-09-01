package store

import (
	"context"
	"time"
)

// Key helpers centralize the shared key schema so the origin shield and the
// edge worker use identical names.

// RateLimitKey returns the sliding-window counter key for an IP.
func RateLimitKey(ip string) string { return "ratelimit:" + ip }

// BanKey returns the ban key for a hashed IP. The argument is the HMAC-SHA256
// of the raw IP (see internal/ip.HashIP) — the raw address is never a key.
func BanKey(hash string) string { return "ban:" + hash }

// DeviceKey returns the permanent device-ban key for a device fingerprint.
func DeviceKey(deviceHash string) string { return "device:" + deviceHash }

// OffenseKey returns the per-hashed-IP offense counter key (TTL 30d).
func OffenseKey(hash string) string { return "offense:" + hash }

// SubnetBanKey returns the permanent subnet-ban key for a hashed subnet prefix.
func SubnetBanKey(subnetHash string) string { return "subnetban:" + subnetHash }

// IpVaultKey returns the encrypted raw-IP vault key for a hashed IP.
func IpVaultKey(hash string) string { return "ipvault:" + hash }

// DarkKey returns the dark-list hash key.
func DarkKey(hash string) string { return "dark:" + hash }

// BanReason is a convenience wrapper that records a ban with a reason and TTL.
func BanReason(ctx context.Context, s Store, hash, reason string, ttl time.Duration) error {
	return s.Set(ctx, BanKey(hash), reason, ttl)
}

// IsBanned reports whether a hashed IP is currently banned.
func IsBanned(ctx context.Context, s Store, hash string) (bool, error) {
	_, err := s.Get(ctx, BanKey(hash))
	if err == ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Offense thresholds and TTLs (mirror the edge worker's store.ts).
const (
	// OffenseTTL is how long an offense counter lives (30 days).
	OffenseTTL = 30 * 24 * time.Hour
	// OffenseBanThreshold is the offense count before an unlimited IP+device
	// ban in normal mode.
	OffenseBanThreshold = 3
	// OffenseBanThresholdAggressive is the offense count before an unlimited
	// IP+device ban in aggressive mode.
	OffenseBanThresholdAggressive = 2
	// SubnetOffenseThreshold is the offense count from one /64 within the
	// window before the whole subnet is banned (swelling protection).
	SubnetOffenseThreshold = 5
	// SubnetOffenseWindow is the window (1h) for the /64 swelling check.
	SubnetOffenseWindow = time.Hour
)

// RecordOffense increments the offense counter for a hashed IP and escalates
// through a strike ladder. Returns the new offense count.
//
// Swelling protection: the FIRST offense only dark-lists (no ban); the SECOND
// issues a temporary IP ban; only after the threshold (3 normal / 2 aggressive)
// do we issue an UNLIMITED IP + device ban. When the same /64 produces
// SubnetOffenseThreshold offenses within SubnetOffenseWindow, the whole subnet
// is banned so IPv6 rotation cannot inflate the ban list.
func RecordOffense(ctx context.Context, s Store, ipHash, deviceHash, subnetHash, reason string, aggressive bool) (int64, error) {
	count, err := s.Incr(ctx, OffenseKey(ipHash))
	if err != nil {
		return 0, err
	}
	_ = s.Expire(ctx, OffenseKey(ipHash), OffenseTTL)

	threshold := OffenseBanThreshold
	if aggressive {
		threshold = OffenseBanThresholdAggressive
	}

	// 2nd offense (normal mode) -> temporary IP ban.
	if !aggressive && count == 2 {
		_ = s.Set(ctx, BanKey(ipHash), "temporary:"+reason, time.Hour)
	}

	// Threshold reached -> unlimited IP + device ban.
	if count >= int64(threshold) {
		_ = s.Set(ctx, BanKey(ipHash), "unlimited:"+reason, 0)
		_ = s.Set(ctx, DeviceKey(deviceHash), "unlimited:"+reason, 0)
	}

	// Subnet swelling: many offenses from one /64 -> ban the whole subnet.
	if subnetHash != "" && count >= SubnetOffenseThreshold {
		subnetReason := "unlimited:subnet-swell:" + reason
		_ = s.Set(ctx, SubnetBanKey(subnetHash), subnetReason, 0)
		_ = s.Set(ctx, BanKey(subnetHash), subnetReason, 0)
	}

	return count, nil
}
