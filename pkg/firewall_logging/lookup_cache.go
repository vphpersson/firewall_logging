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

type cacheEntry[V any] struct {
	value   V
	expires time.Time
}

// lookupCache memoises a name lookup for a bounded time. A failed lookup is
// cached as the empty string too, since a name that cannot be resolved is the
// expensive case and is no more likely to resolve on the very next packet.
type lookupCache[K comparable, V any] struct {
	mutex   sync.Mutex
	entries map[K]cacheEntry[V]
	ttl     time.Duration
	now     func() time.Time
	resolve func(K) V
	// retryEmpty, when set, decides that a resolved value is not worth caching.
	// Names are cached even when they fail to resolve, but state that is
	// expected to appear shortly must not be: an interface created moments ago
	// has no address until networkd applies one, and caching that emptiness
	// would suppress the answer for a whole ttl.
	retryEmpty func(V) bool
}

func newLookupCache[K comparable, V any](resolve func(K) V) *lookupCache[K, V] {
	return &lookupCache[K, V]{
		entries: make(map[K]cacheEntry[V]),
		ttl:     lookupCacheTtl,
		now:     time.Now,
		resolve: resolve,
	}
}

func (cache *lookupCache[K, V]) get(key K) V {
	now := cache.now()

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	if entry, ok := cache.entries[key]; ok && now.Before(entry.expires) {
		return entry.value
	}

	value := cache.resolve(key)
	if cache.retryEmpty != nil && cache.retryEmpty(value) {
		return value
	}

	cache.entries[key] = cacheEntry[V]{value: value, expires: now.Add(cache.ttl)}

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

// interfaceNetworksCache memoises the networks configured on an interface, so
// the source address of a logged packet can be tested for being on-link. The
// nflog hardware address is the sender of the frame, i.e. the previous hop; it
// identifies the origin only when the origin is on the arrival segment.
var interfaceNetworksCache = newLookupCache(func(index int) []*net.IPNet {
	networkInterface, err := net.InterfaceByIndex(index)
	if networkInterface == nil || err != nil {
		return nil
	}

	addresses, err := networkInterface.Addrs()
	if err != nil {
		return nil
	}

	networks := make([]*net.IPNet, 0, len(addresses))
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok && network != nil {
			networks = append(networks, network)
		}
	}

	return networks
})

func init() {
	// An interface that exists but has no address yet is the normal state for a
	// per-station AP-VLAN between hostapd creating it and networkd addressing
	// it. Caching that would blank source.mac for the first minute after every
	// association.
	interfaceNetworksCache.retryEmpty = func(networks []*net.IPNet) bool {
		return len(networks) == 0
	}
}

// sourceIsOnLink reports whether an address belongs to a network configured on
// the interface a packet arrived on.
func sourceIsOnLink(interfaceIndex int, ipAddress net.IP) bool {
	if ipAddress == nil {
		return false
	}

	for _, network := range interfaceNetworksCache.get(interfaceIndex) {
		if network.Contains(ipAddress) {
			return true
		}
	}

	return false
}
