package main

import (
	"sync"
	"time"
)

// ipLimiter enforces two per-client-IP limits:
//   - a sliding-window rate of NEW connections (ratePerMin), and
//   - a ceiling on concurrently-open connections (maxConcurrent).
//
// It is safe for concurrent use. Window bookkeeping is lazy: stale timestamps
// are pruned on access, and empty entries are dropped so the map does not grow
// without bound.
type ipLimiter struct {
	mu            sync.Mutex
	ratePerMin    int
	maxConcurrent int
	now           func() time.Time

	starts map[string][]time.Time // connection-open timestamps in the last minute
	active map[string]int         // currently-open connections
}

func newIPLimiter(ratePerMin, maxConcurrent int) *ipLimiter {
	return &ipLimiter{
		ratePerMin:    ratePerMin,
		maxConcurrent: maxConcurrent,
		now:           time.Now,
		starts:        map[string][]time.Time{},
		active:        map[string]int{},
	}
}

// acquire attempts to reserve a connection slot for ip. On success it returns
// a release func that MUST be called when the connection closes. On failure it
// returns (nil, false) and reserves nothing.
func (l *ipLimiter) acquire(ip string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := l.now().Add(-time.Minute)
	kept := l.starts[ip][:0]
	for _, t := range l.starts[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.starts, ip)
	} else {
		l.starts[ip] = kept
	}

	if l.ratePerMin > 0 && len(kept) >= l.ratePerMin {
		return nil, false
	}
	if l.maxConcurrent > 0 && l.active[ip] >= l.maxConcurrent {
		return nil, false
	}

	l.starts[ip] = append(l.starts[ip], l.now())
	l.active[ip]++

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.active[ip]--
			if l.active[ip] <= 0 {
				delete(l.active, ip)
			}
		})
	}, true
}
