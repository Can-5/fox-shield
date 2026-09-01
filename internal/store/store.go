// Package store provides the persistence layer for fox-shield.
//
// It exposes a Store interface with an in-memory fallback implementation
// (MemoryStore) and a Redis-backed implementation (RedisStore). The same key
// schema is shared with the edge worker's KV namespace:
//
//	ratelimit:{ip}   -> sliding-window request counters
//	ban:{ip}         -> banned IPs (value = reason)
//	dark:{hash}      -> dark-listed request hashes (value = reason)
//
// If Redis is unavailable (no REDIS_URL or connection error) the shield falls
// back to MemoryStore so the origin proxy still runs.
package store

import (
	"container/list"
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned when a key does not exist in the store.
var ErrNotFound = errors.New("store: key not found")

// Store is the persistence contract used by the shield middleware chain.
type Store interface {
	// Get returns the value stored under key, or ErrNotFound.
	Get(ctx context.Context, key string) (string, error)
	// Set stores value under key with an optional TTL (0 = no expiry).
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	// Incr atomically increments the integer stored under key and returns the
	// new value. If the key does not exist it is created as 1.
	Incr(ctx context.Context, key string) (int64, error)
	// Expire sets a TTL on an existing key.
	Expire(ctx context.Context, key string, ttl time.Duration) error
	// Delete removes a key.
	Delete(ctx context.Context, key string) error
	// Close releases any underlying resources.
	Close() error
}

// MemoryStore is a thread-safe in-memory implementation of Store. It is used
// as a fallback when Redis is not configured or unreachable.
//
// Ban entries (keys prefixed with "ban:") are bounded by maxBans using an LRU
// eviction policy so an attacker rotating many distinct IPs cannot exhaust
// memory by creating unbounded ban records.
type MemoryStore struct {
	mu    sync.RWMutex
	items map[string]memItem
	// banLRU tracks ban keys in recency order (front = most recently used) so
	// the oldest ban can be evicted when the cap is reached.
	banLRU    *list.List
	banOrder  map[string]*list.Element
}

// maxBans caps the number of in-memory ban records to prevent memory
// exhaustion from an attacker rotating many distinct IPs.
const maxBans = 50_000

type memItem struct {
	value     string
	expiresAt time.Time
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		items:    make(map[string]memItem),
		banLRU:   list.New(),
		banOrder: make(map[string]*list.Element),
	}
}

func (m *MemoryStore) Get(_ context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	it, ok := m.items[key]
	if !ok {
		return "", ErrNotFound
	}
	if !it.expiresAt.IsZero() && time.Now().After(it.expiresAt) {
		delete(m.items, key)
		return "", ErrNotFound
	}
	return it.value, nil
}

func (m *MemoryStore) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp := time.Time{}
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	m.items[key] = memItem{value: value, expiresAt: exp}
	if strings.HasPrefix(key, "ban:") {
		m.touchBan(key)
	}
	return nil
}

// touchBan records a ban key as most-recently-used and evicts the oldest ban
// when the cap is exceeded. Callers must hold m.mu.
func (m *MemoryStore) touchBan(key string) {
	if el, ok := m.banOrder[key]; ok {
		m.banLRU.MoveToFront(el)
		return
	}
	el := m.banLRU.PushFront(key)
	m.banOrder[key] = el
	if m.banLRU.Len() > maxBans {
		oldest := m.banLRU.Back()
		if oldest != nil {
			oldKey := oldest.Value.(string)
			delete(m.banOrder, oldKey)
			delete(m.items, oldKey)
			m.banLRU.Remove(oldest)
		}
	}
}

func (m *MemoryStore) Incr(_ context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.items[key]
	if !ok || (!it.expiresAt.IsZero() && time.Now().After(it.expiresAt)) {
		m.items[key] = memItem{value: "1"}
		return 1, nil
	}
	n, err := parseCount(it.value)
	if err != nil {
		n = 0
	}
	n++
	m.items[key] = memItem{value: itoa(n), expiresAt: it.expiresAt}
	return n, nil
}

func (m *MemoryStore) Expire(_ context.Context, key string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.items[key]
	if !ok {
		return ErrNotFound
	}
	it.expiresAt = time.Now().Add(ttl)
	m.items[key] = it
	return nil
}

func (m *MemoryStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
	if strings.HasPrefix(key, "ban:") {
		if el, ok := m.banOrder[key]; ok {
			m.banLRU.Remove(el)
			delete(m.banOrder, key)
		}
	}
	return nil
}

func (m *MemoryStore) Close() error { return nil }

// Snapshot returns a copy of all non-expired values currently in the store.
// It is used by the similarity detector to scan the dark list.
func (m *MemoryStore) Snapshot() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	out := make([]string, 0, len(m.items))
	for k, it := range m.items {
		if !it.expiresAt.IsZero() && now.After(it.expiresAt) {
			continue
		}
		_ = k
		out = append(out, it.value)
	}
	return out
}

// parseCount converts a stored string to an int64.
func parseCount(s string) (int64, error) {
	var n int64
	if len(s) == 0 {
		return 0, errors.New("store: empty count")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, errors.New("store: invalid count")
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}

// itoa converts an int64 to a decimal string without importing strconv.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
