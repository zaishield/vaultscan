package emergency

import (
	"sync"
	"testing"
	"time"
)

func TestEmergency_InitialState(t *testing.T) {
	l := New()
	if l.Stopped() {
		t.Error("fresh listener should not be stopped")
	}
	if !l.Since().IsZero() {
		t.Error("Since() should be zero before Trigger")
	}
}

func TestEmergency_TriggerSetsStopped(t *testing.T) {
	l := New()
	before := time.Now()
	l.Trigger()
	if !l.Stopped() {
		t.Error("expected Stopped after Trigger")
	}
	if l.Since().Before(before) || l.Since().After(time.Now()) {
		t.Errorf("Since() = %v, expected within [%v, now]", l.Since(), before)
	}
}

func TestEmergency_Reset(t *testing.T) {
	l := New()
	l.Trigger()
	l.Reset()
	if l.Stopped() {
		t.Error("Reset should clear Stopped")
	}
}

func TestEmergency_ConcurrentTriggers(t *testing.T) {
	l := New()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Trigger()
		}()
	}
	wg.Wait()
	if !l.Stopped() {
		t.Error("expected Stopped after concurrent triggers")
	}
}
