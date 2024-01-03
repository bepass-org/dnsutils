package cache

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// If whole cache items has equal expiration why Item
// has Expiration field? and why rely on it?
// Whats the point of mu?
// Why Cache type is not interface?
// Why passing map not by reference?
// Shouldn't DeleteExpired get called?
// Shouldn't stopJanitor be Cache method?

var ErrItemDoesntExist = errors.New("item doesn't exist")

// Item represents an item in the cache.
type Item struct {
	Object     interface{}
	Expiration int64
}

// Expired returns true if the item has expired.
func (item *Item) Expired() bool {
	if item == nil || item.Expiration == 0 {
		return false
	}
	return time.Now().UnixNano() > item.Expiration
}

// Cache represents the main cache structure.
type Cache struct {
	*cache
}

// cache holds the actual cache data and related methods.
type cache struct {
	expiration time.Duration
	items      sync.Map
	mu         sync.RWMutex
	onExpired  func()
	janitor    *janitor
}

// Set adds an item to the cache, replacing any existing item.
func (c *cache) Set(k string, x interface{}) {
	e := int64(0)
	if c.expiration > 0 {
		e = time.Now().Add(c.expiration).UnixNano()
	}
	c.items.Store(k, &Item{Object: x, Expiration: e})
}

// Replace sets a new value for the cache key only if it already exists. Returns an error otherwise.
func (c *cache) Replace(k string, x interface{}) error {
	_, found := c.Get(k)
	if !found {
		return fmt.Errorf("key %s: %w", k, ErrItemDoesntExist)
	}
	c.Set(k, x)
	return nil
}

// Get retrieves an item from the cache. Returns the item or nil, and a bool indicating whether the key was found.
func (c *cache) Get(k string) (interface{}, bool) {
	item, found := c.items.Load(k)
	if !found || item.(*Item).Object == nil {
		return nil, false
	}
	return item.(*Item).Object, true
}

// GetAll returns all keys in the cache or an empty map.
func (c *cache) GetAll() map[string]interface{} {
	items := make(map[string]interface{})
	c.items.Range(func(k, v interface{}) bool {
		if obj := v.(*Item).Object; obj != nil {
			items[k.(string)] = obj
		}
		return true
	})
	return items
}

// Delete removes an item from the cache. Does nothing if the key is not in the cache.
func (c *cache) Delete(k string) {
	c.items.Delete(k)
}

// DeleteExpired deletes all expired items from the cache.
func (c *cache) DeleteExpired() {
	c.items.Range(func(k, v interface{}) bool {
		item := v.(*Item)
		if item.Expired() {
			c.items.Delete(k)
		}
		return true
	})
}

// OnExpired sets an (optional) function that is called when the cache expires.
func (c *cache) OnExpired(f func()) {
	c.onExpired = f
}

// ItemCount returns the number of items in the cache, including expired items.
func (c *cache) ItemCount() int {
	count := 0
	c.items.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// Flush deletes all items from the cache.
func (c *cache) Flush() {
	c.items = sync.Map{}
}

// janitor periodically cleans up expired items.
type janitor struct {
	Interval time.Duration
	stop     chan bool
}

// handleExpired is fired by the ticker and executes the onExpired function.
func (c *cache) handleExpired() {
	if c.onExpired != nil {
		c.onExpired()
	}
}

// Run starts the janitor to handle expired items.
func (j *janitor) Run(c *cache) {
	ticker := time.NewTicker(j.Interval)
	for {
		select {
		case <-ticker.C:
			c.handleExpired()
		case <-j.stop:
			ticker.Stop()
			return
		}
	}
}

// stopJanitor stops the janitor when the cache is garbage collected.
func stopJanitor(c *Cache) {
	c.janitor.stop <- true
}

// runJanitor starts the janitor to handle expired items.
func runJanitor(c *cache, ex time.Duration) {
	j := &janitor{
		Interval: ex,
		stop:     make(chan bool, 1),
	}
	c.janitor = j
	go j.Run(c)
}

// newCache creates a new cache with the given expiration duration and initial map.
func newCache(ex time.Duration, m sync.Map) *cache {
	if ex <= 0 {
		ex = -1
	}
	c := &cache{
		expiration: ex,
		items:      m,
	}
	return c
}

// newCacheWithJanitor creates a new cache with the janitor and sets up the finalizer.
func newCacheWithJanitor(ex time.Duration, m sync.Map) *Cache {
	c := newCache(ex, m)
	C := &Cache{c}
	if ex > 0 {
		runJanitor(c, ex)
		runtime.SetFinalizer(C, stopJanitor)
	}
	return C
}

// NewCache returns a new cache with a given expiration duration. If the expiration duration is less than 1 (i.e., No Expiration),
// the items in the cache never expire (by default), and must be deleted manually.
// The OnExpired callback method is ignored, too.
func NewCache(expiration time.Duration) *Cache {
	return newCacheWithJanitor(expiration, sync.Map{})
}
