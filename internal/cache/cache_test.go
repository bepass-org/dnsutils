package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestItemExired(t *testing.T) {
	tests := []struct {
		item Item
		exp  bool
	}{
		{
			Item{Object: nil, Expiration: time.Now().Add(time.Hour * 2).UnixNano()},
			false,
		},
		{
			Item{Object: 2, Expiration: 0},
			false,
		},
		{
			Item{Object: 2, Expiration: time.Now().Add(-time.Hour * 2).UnixNano()},
			true,
		},
		{
			Item{Object: 2, Expiration: time.Now().Add(time.Hour * 2).UnixNano()},
			false,
		},
	}
	for i, test := range tests {
		res := test.item.Expired()
		assert.Equal(t, test.exp, res, "test %d", i)
	}
}

func TestCacheSet(t *testing.T) {
	tests := []struct {
		key   string
		value interface{}
	}{
		{"a", 2},
	}
	for i, test := range tests {
		cache := NewCache(time.Hour)
		cache.Set(test.key, test.value)

		ret, found := cache.Get(test.key)
		if !found {
			t.Errorf("test %d: expected item to exist in cache", i)
			continue
		}
		assert.Equal(t, test.value, ret, "test %d", i)
	}
}

func TestCacheReplace(t *testing.T) {
	tests := []struct {
		initialItems map[string]interface{}
		key          string
		value        interface{}
	}{
		{
			map[string]interface{}{"a": 1, "b": 2},
			"a",
			3,
		},
		{
			map[string]interface{}{"a": 1, "b": 2},
			"c",
			3,
		},
	}
	for i, test := range tests {
		cache := NewCache(time.Hour)
		for k, v := range test.initialItems {
			cache.Set(k, v)
		}

		err := cache.Replace(test.key, test.value)
		_, exists := test.initialItems[test.key]
		if !exists {
			assert.ErrorIs(t, err, ErrItemDoesntExist)
			continue
		}
		assert.Nil(t, err, "test %d", i)

		ret, _ := cache.Get(test.key)
		assert.Equal(t, test.value, ret, "test %d", i)
	}
}

func TestCacheGet(t *testing.T) {
	tests := []struct {
		initialItems map[string]interface{}
		key          string
		value        interface{}
	}{
		{
			map[string]interface{}{"a": 1, "b": 2},
			"a",
			1,
		},
		{
			map[string]interface{}{"a": 1, "b": 2},
			"c",
			3,
		},
	}
	for i, test := range tests {
		cache := NewCache(time.Hour)
		for k, v := range test.initialItems {
			cache.Set(k, v)
		}

		ret, existsInCache := cache.Get(test.key)
		_, existsInInitial := test.initialItems[test.key]
		if !existsInInitial {
			assert.False(t, existsInCache, "test %d", i)
			continue
		}
		assert.Equal(t, test.value, ret, "test %d", i)
	}
}

func TestCacheGetAll(t *testing.T) {
	tests := []struct {
		initialItems map[string]interface{}
	}{
		{
			map[string]interface{}{"a": 1, "b": 2},
		},
		{
			map[string]interface{}{"a": 4, "x": 31},
		},
	}
	for i, test := range tests {
		cache := NewCache(time.Hour)
		for k, v := range test.initialItems {
			cache.Set(k, v)
		}

		ret := cache.GetAll()
		assert.Equal(t, test.initialItems, ret, "test %d", i)
	}
}

func TestCacheDelete(t *testing.T) {
	tests := []struct {
		initialItems map[string]interface{}
		key          string
	}{
		{
			map[string]interface{}{"a": 1, "b": 2},
			"a",
		},
		{
			map[string]interface{}{"z": 1, "ql": 2},
			"c",
		},
	}
	for i, test := range tests {
		cache := NewCache(time.Hour)
		for k, v := range test.initialItems {
			cache.Set(k, v)
		}

		cache.Delete(test.key)
		_, exists := cache.Get(test.key)
		assert.False(t, exists, "test %d", i)
	}
}

func TestCacheDeleteExpired(t *testing.T) {
	tests := []struct {
		initialItems map[string]interface{}
		expiration   time.Duration
		exp          map[string]interface{}
	}{
		{
			map[string]interface{}{"a": 1, "b": 2},
			4 * time.Millisecond,
			map[string]interface{}{},
		},
		{
			map[string]interface{}{"z": 1, "ql": 2},
			0,
			map[string]interface{}{"z": 1, "ql": 2},
		},
	}
	for i, test := range tests {
		cache := NewCache(test.expiration)
		for k, v := range test.initialItems {
			cache.Set(k, v)
		}
		time.Sleep(test.expiration)

		cache.DeleteExpired()
		ret := cache.GetAll()
		assert.Equal(t, test.exp, ret, "test %d", i)
	}
}

func TestCacheOnExpired(t *testing.T) {
	initialItems := map[string]interface{}{"a": 1, "b": 2}
	cache := NewCache(time.Hour)
	for k, v := range initialItems {
		cache.Set(k, v)
	}
	count := 0
	cache.OnExpired(func() { count++ })

	cache.handleExpired()
	assert.Equal(t, 1, count)
}

func TestCacheItemCount(t *testing.T) {
	tests := []struct {
		initialItems map[string]interface{}
		exp          int
	}{
		{
			map[string]interface{}{"a": 1, "b": 2},
			2,
		},
		{
			map[string]interface{}{"z": 1},
			1,
		},
	}
	for i, test := range tests {
		cache := NewCache(time.Hour)
		for k, v := range test.initialItems {
			cache.Set(k, v)
		}

		ret := cache.ItemCount()
		assert.Equal(t, test.exp, ret, "test %d", i)
	}
}

func TestCacheFlush(t *testing.T) {
	initialItems := map[string]interface{}{"a": 1, "b": 2}
	cache := NewCache(time.Hour)
	for k, v := range initialItems {
		cache.Set(k, v)
	}

	assert.Equal(t, len(initialItems), cache.ItemCount())
	cache.Flush()
	assert.Equal(t, 0, cache.ItemCount())
}

func TestJanitor(t *testing.T) {
	expiration := time.Millisecond * 3
	cache := NewCache(expiration)
	count := 0
	cache.OnExpired(func() { count++ })

	time.Sleep(expiration)
	assert.Equal(t, 1, count)
}

func TestJanitorStop(t *testing.T) {
	expiration := time.Millisecond * 3
	cache := NewCache(expiration)
	count := 0
	cache.OnExpired(func() { count++ })
	stopJanitor(cache)

	time.Sleep(expiration)
	assert.Equal(t, 0, count)
}
