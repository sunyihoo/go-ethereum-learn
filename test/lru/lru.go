package lru

import "sync"

type Cache[K comparable, V any] struct {
	cache BasicLRU[K, V]
	mu    sync.Mutex
}

func NewCache[K comparable, V any](capacity int) *Cache[K, V] {
	return &Cache[K, V]{
		cache: NewBasicLRU[K, V](capacity),
	}
}

func (c *Cache[K, V]) Add(key K, value V) (evicted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.cache.Add(key, value)
}

func (c *Cache[K, V]) Contains(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.cache.Contains(key)
}

func (c *Cache[K, V]) Get(key K) (value V, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.cache.Get(key)
}

func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.cache.Len()
}

func (c *Cache[K, V]) Peek(key K) (value V, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.cache.Peek(key)
}

func (c *Cache[K, V]) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Purge()
}

func (c *Cache[K, V]) Remove(key K) (evicted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.cache.Remove(key)
}

func (c *Cache[K, V]) Keys() []K {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.cache.Keys()
}
