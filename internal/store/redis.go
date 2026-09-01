package store

import (
	"context"
	"time"
)

// RedisStore is a Store backed by a Redis server. It is a thin adapter over
// the go-redis client. To keep the scaffold dependency-light and runnable
// without external modules, the Redis client is injected via an interface so
// the package compiles even when go-redis is not vendored.
//
// In a full build, wire it with:
//
//	rdb := redis.NewClient(&redis.Options{Addr: addr})
//	s := store.NewRedisStore(rdb)
type RedisStore struct {
	client RedisClient
}

// RedisClient is the minimal subset of the go-redis client used by the store.
type RedisClient interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Incr(ctx context.Context, key string) (int64, error)
	Expire(ctx context.Context, key string, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
	Close() error
}

// NewRedisStore wraps a RedisClient as a Store.
func NewRedisStore(client RedisClient) *RedisStore {
	return &RedisStore{client: client}
}

func (r *RedisStore) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key)
}

func (r *RedisStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl)
}

func (r *RedisStore) Incr(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key)
}

func (r *RedisStore) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return r.client.Expire(ctx, key, ttl)
}

func (r *RedisStore) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key)
}

func (r *RedisStore) Close() error { return r.client.Close() }
