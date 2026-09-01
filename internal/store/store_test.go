package store

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStoreBanCapEvictsOldest(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()

	// Insert more bans than the cap to force LRU eviction.
	for i := 0; i < maxBans+10; i++ {
		key := BanKey(ipFor(i))
		if err := m.Set(ctx, key, "reason", time.Minute); err != nil {
			t.Fatalf("Set(%d): %v", i, err)
		}
	}

	// The oldest 10 bans must have been evicted.
	for i := 0; i < 10; i++ {
		if _, err := m.Get(ctx, BanKey(ipFor(i))); err == nil {
			t.Fatalf("ban %d should have been evicted by LRU cap", i)
		}
	}

	// The most recent bans must still be present.
	for i := maxBans; i < maxBans+10; i++ {
		if _, err := m.Get(ctx, BanKey(ipFor(i))); err != nil {
			t.Fatalf("ban %d should still be present: %v", i, err)
		}
	}
}

func TestMemoryStoreBanDeleteRemovesFromLRU(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	key := BanKey("203.0.113.9")
	if err := m.Set(ctx, key, "reason", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, key); err == nil {
		t.Fatal("deleted ban should not be found")
	}
}

func ipFor(i int) string {
	// Generate unique IPs across the full 203.0.x.x space (62500 distinct
	// addresses) so the LRU cap test never reuses a key.
	return "203.0." + itoa(int64(i/250)) + "." + itoa(int64(i%250+1))
}
