package uma

import (
	"errors"
	"time"
)

// NonceCache is an interface for a caching of nonces used in signatures. This is used to prevent replay attacks.
//
// Implementations of this interface should be thread-safe.
type NonceCache interface {
	// CheckAndSaveNonce checks if the given nonce has been used before, and if not, saves it and returns nil.
	// If the nonce has been used before, or if timestamp is too old, returns an error.
	CheckAndSaveNonce(nonce string, timestamp time.Time) error

	// PurgeNoncesOlderThan purges all nonces older than the given timestamp.
	// This allows the cache to be pruned periodically while still preventing replay attacks by holding onto an earliest
	// timestamp that is still valid.
	PurgeNoncesOlderThan(timestamp time.Time)
}

// InMemoryNonceCache is an in-memory implementation of NonceCache.
// It is not recommended to use this in production, as it will not persist across restarts. You likely want to implement
// your own NonceCache that persists to a database of some sort.
type InMemoryNonceCache struct {
	cache                map[string]time.Time
	oldestValidTimestamp time.Time
}

func NewInMemoryNonceCache(oldestValidTimestamp time.Time) *InMemoryNonceCache {
	return &InMemoryNonceCache{
		cache:                make(map[string]time.Time),
		oldestValidTimestamp: oldestValidTimestamp,
	}
}

func (c *InMemoryNonceCache) CheckAndSaveNonce(nonce string, timestamp time.Time) error {
	if _, ok := c.cache[nonce]; ok {
		return errors.New("nonce already used")
	}
	if timestamp.Before(c.oldestValidTimestamp) {
		return errors.New("timestamp too old")
	}
	c.cache[nonce] = timestamp
	return nil
}

func (c *InMemoryNonceCache) PurgeNoncesOlderThan(timestamp time.Time) {
	for nonce, nonceTimestamp := range c.cache {
		if nonceTimestamp.Before(timestamp) {
			delete(c.cache, nonce)
		}
	}
	c.oldestValidTimestamp = timestamp
}
