package process

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestObserverZeroDurationTakesOneSnapshot(t *testing.T) {
	clock := newFakeClock()
	calls := 0
	observed, err := NewObserver(clock).Observe(context.Background(), ObserveOptions{Duration: 0, Interval: time.Second}, func(context.Context) ([]ProcessFact, error) {
		calls++
		return []ProcessFact{{PID: 10, StartTime: 100}}, nil
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if calls != 1 || len(observed) != 1 || observed[0].Observations != 1 {
		t.Fatalf("calls/observed = %d/%#v", calls, observed)
	}
}

func TestObserverDefaultWindowSchedulesThirtySeconds(t *testing.T) {
	options := DefaultObserveOptions()
	if options.Duration != 30*time.Second {
		t.Fatalf("default duration = %s", options.Duration)
	}
	options.Interval = 10 * time.Second
	clock := newFakeClock()
	calls := 0
	_, err := NewObserver(clock).Observe(context.Background(), options, func(context.Context) ([]ProcessFact, error) {
		calls++
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if calls != 4 || !reflect.DeepEqual(clock.waits, []time.Duration{10 * time.Second, 10 * time.Second, 10 * time.Second}) {
		t.Fatalf("calls/waits = %d/%#v", calls, clock.waits)
	}
}

func TestObserverDistinguishesPIDReuseByStartTime(t *testing.T) {
	clock := newFakeClock()
	snapshots := [][]ProcessFact{
		{{PID: 42, StartTime: 100, Name: "old"}},
		{{PID: 42, StartTime: 100, Name: "old"}},
		{{PID: 42, StartTime: 200, Name: "new"}},
	}
	index := 0
	observed, err := NewObserver(clock).Observe(context.Background(), ObserveOptions{Duration: 2 * time.Second, Interval: time.Second}, func(context.Context) ([]ProcessFact, error) {
		value := snapshots[index]
		index++
		return value, nil
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if len(observed) != 2 || observed[0].Process.StartTime != 100 || observed[0].Observations != 2 || observed[1].Process.StartTime != 200 {
		t.Fatalf("observed PID reuse = %#v", observed)
	}
}

type fakeClock struct {
	now   time.Time
	waits []time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) After(duration time.Duration) <-chan time.Time {
	c.waits = append(c.waits, duration)
	c.now = c.now.Add(duration)
	ready := make(chan time.Time, 1)
	ready <- c.now
	return ready
}
