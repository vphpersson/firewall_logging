package firewall_logging

import (
	"net"
	"os/user"
	"sync"
	"time"
)

// lookupCacheTtl bounds how long a resolved name is reused. Interface names,
// users and groups are looked up once per logged packet, which on a busy
// firewall means a netlink round trip and an NSS resolution per packet; a short
// time to live turns nearly all of those into a map read while still picking up
// a renamed interface or an edited passwd entry without a restart.
const lookupCacheTtl = time.Minute

type cacheEntry struct {
	value   string
	expires time.Time
}

// lookupCache memoises a name lookup for a bounded time. A failed lookup is
// cached as the empty string too, since a name that cannot be resolved is the
// expensive case and is no more likely to resolve on the very next packet.
type lookupCache[K comparable] struct {
	mutex   sync.Mutex
	entries map[K]cacheEntry
	ttl     time.Duration
	now     func() time.Time
	resolve func(K) string
}

func newLookupCache[K comparable](resolve func(K) string) *lookupCache[K] {
	return &lookupCache[K]{
		entries: make(map[K]cacheEntry),
		ttl:     lookupCacheTtl,
		now:     time.Now,
		resolve: resolve,
	}
}

func (cache *lookupCache[K]) get(key K) string {
	now := cache.now()

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	if entry, ok := cache.entries[key]; ok && now.Before(entry.expires) {
		return entry.value
	}

	value := cache.resolve(key)
	cache.entries[key] = cacheEntry{value: value, expires: now.Add(cache.ttl)}

	return value
}

var interfaceNameCache = newLookupCache(func(index int) string {
	networkInterface, _ := net.InterfaceByIndex(index)
	if networkInterface == nil {
		return ""
	}

	return networkInterface.Name
})

var userNameCache = newLookupCache(func(id string) string {
	lookupUser, _ := user.LookupId(id)
	if lookupUser == nil {
		return ""
	}

	return lookupUser.Username
})

var groupNameCache = newLookupCache(func(id string) string {
	lookupGroup, _ := user.LookupGroupId(id)
	if lookupGroup == nil {
		return ""
	}

	return lookupGroup.Name
})
