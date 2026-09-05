package firewall_logging

import (
	"sync"
	"testing"
	"time"
)

// newTestCache builds a cache whose clock is driven by the returned pointer and
// which counts how many times the underlying lookup actually ran.
func newTestCache(values map[string]string) (*lookupCache[string, string], *time.Time, *int) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	calls := 0

	cache := &lookupCache[string, string]{
		entries: make(map[string]cacheEntry[string]),
		ttl:     time.Minute,
		now:     func() time.Time { return now },
		resolve: func(key string) string {
			calls++
			return values[key]
		},
	}

	return cache, &now, &calls
}

func TestLookupCache(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		key           string
		advance       time.Duration
		expectedValue string
		expectedCalls int
	}{
		{
			name:          "a repeated lookup within the ttl is served from the cache",
			key:           "known",
			advance:       0,
			expectedValue: "resolved",
			expectedCalls: 1,
		},
		{
			name:          "a lookup just before the ttl expires is still cached",
			key:           "known",
			advance:       time.Minute - time.Nanosecond,
			expectedValue: "resolved",
			expectedCalls: 1,
		},
		{
			name:          "the lookup runs again once the ttl has passed",
			key:           "known",
			advance:       time.Minute,
			expectedValue: "resolved",
			expectedCalls: 2,
		},
		{
			name:          "a failed lookup is cached too",
			key:           "unknown",
			advance:       0,
			expectedValue: "",
			expectedCalls: 1,
		},
		{
			name:          "a failed lookup is retried after the ttl",
			key:           "unknown",
			advance:       time.Minute,
			expectedValue: "",
			expectedCalls: 2,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			cache, now, calls := newTestCache(map[string]string{"known": "resolved"})

			if value := cache.get(testCase.key); value != testCase.expectedValue {
				t.Errorf("expected %q on the first lookup, got %q", testCase.expectedValue, value)
			}

			*now = now.Add(testCase.advance)

			if value := cache.get(testCase.key); value != testCase.expectedValue {
				t.Errorf("expected %q on the second lookup, got %q", testCase.expectedValue, value)
			}

			if *calls != testCase.expectedCalls {
				t.Errorf("expected %d underlying lookups, got %d", testCase.expectedCalls, *calls)
			}
		})
	}
}

func TestLookupCacheDistinctKeys(t *testing.T) {
	t.Parallel()

	cache, _, calls := newTestCache(map[string]string{"a": "first", "b": "second"})

	if value := cache.get("a"); value != "first" {
		t.Errorf("expected 'first', got %q", value)
	}

	if value := cache.get("b"); value != "second" {
		t.Errorf("expected 'second', got %q", value)
	}

	if value := cache.get("a"); value != "first" {
		t.Errorf("expected 'first' from the cache, got %q", value)
	}

	if *calls != 2 {
		t.Errorf("expected 2 underlying lookups, got %d", *calls)
	}
}

func TestLookupCacheIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	// The real caches are read from the nflog callback, so concurrent use must
	// not race. Run under -race to make this meaningful.
	cache := newLookupCache(func(key int) string { return "value" })

	var waitGroup sync.WaitGroup
	for index := range 32 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if value := cache.get(index % 4); value != "value" {
				t.Errorf("expected 'value', got %q", value)
			}
		}()
	}

	waitGroup.Wait()
}
