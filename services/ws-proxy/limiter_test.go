package main

import (
	"testing"
	"time"
)

func TestLimiterConcurrentCeiling(t *testing.T) {
	l := newIPLimiter(0, 2) // no rate cap; max 2 concurrent
	r1, ok := l.acquire("1.2.3.4")
	if !ok {
		t.Fatal("first acquire should succeed")
	}
	_, ok = l.acquire("1.2.3.4")
	if !ok {
		t.Fatal("second acquire should succeed")
	}
	if _, ok := l.acquire("1.2.3.4"); ok {
		t.Fatal("third concurrent acquire should be refused")
	}
	// A different IP is unaffected.
	if _, ok := l.acquire("5.6.7.8"); !ok {
		t.Fatal("different IP should be allowed")
	}
	// Releasing frees a slot.
	r1()
	if _, ok := l.acquire("1.2.3.4"); !ok {
		t.Fatal("acquire after release should succeed")
	}
}

func TestLimiterReleaseIdempotent(t *testing.T) {
	l := newIPLimiter(0, 1)
	rel, _ := l.acquire("1.2.3.4")
	rel()
	rel() // must not drive active negative
	if _, ok := l.acquire("1.2.3.4"); !ok {
		t.Fatal("acquire should succeed after idempotent release")
	}
}

func TestLimiterRateWindow(t *testing.T) {
	l := newIPLimiter(3, 0) // 3 new conns/min; no concurrency cap
	base := time.Now()
	l.now = func() time.Time { return base }

	for i := 0; i < 3; i++ {
		if _, ok := l.acquire("9.9.9.9"); !ok {
			t.Fatalf("acquire %d within rate should succeed", i)
		}
	}
	if _, ok := l.acquire("9.9.9.9"); ok {
		t.Fatal("4th acquire within the same minute should be rate-limited")
	}
	// Advance past the window: the old starts age out.
	l.now = func() time.Time { return base.Add(61 * time.Second) }
	if _, ok := l.acquire("9.9.9.9"); !ok {
		t.Fatal("acquire after window rollover should succeed")
	}
}
