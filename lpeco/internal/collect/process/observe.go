package process

import (
	"context"
	"fmt"
	"sort"
	"time"
)

const DefaultObservationDuration = 30 * time.Second

type Clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                                { return time.Now().UTC() }
func (realClock) After(duration time.Duration) <-chan time.Time { return time.After(duration) }

type ObserveOptions struct {
	Duration time.Duration
	Interval time.Duration
}

func DefaultObserveOptions() ObserveOptions {
	return ObserveOptions{Duration: DefaultObservationDuration, Interval: time.Second}
}

type ObservedProcess struct {
	Process      ProcessFact `json:"process"`
	FirstSeen    time.Time   `json:"first_seen"`
	LastSeen     time.Time   `json:"last_seen"`
	Observations int         `json:"observations"`
}

type Snapshotter func(context.Context) ([]ProcessFact, error)

type Observer struct {
	clock Clock
}

func NewObserver(clock Clock) *Observer {
	if clock == nil {
		clock = realClock{}
	}
	return &Observer{clock: clock}
}

func (o *Observer) Observe(ctx context.Context, options ObserveOptions, snapshot Snapshotter) ([]ObservedProcess, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("process snapshotter is required")
	}
	if options.Duration < 0 {
		return nil, fmt.Errorf("observation duration cannot be negative")
	}
	if options.Duration > 0 && options.Interval <= 0 {
		return nil, fmt.Errorf("observation interval must be positive")
	}
	observed := make(map[string]*ObservedProcess)
	capture := func() error {
		processes, err := snapshot(ctx)
		if err != nil {
			return err
		}
		now := o.clock.Now()
		for _, process := range processes {
			key := fmt.Sprintf("%d:%d", process.PID, process.StartTime)
			entry, exists := observed[key]
			if !exists {
				entry = &ObservedProcess{Process: process, FirstSeen: now}
				observed[key] = entry
			}
			entry.Process = process
			entry.LastSeen = now
			entry.Observations++
		}
		return nil
	}
	if err := capture(); err != nil {
		return nil, err
	}
	for elapsed := time.Duration(0); elapsed < options.Duration; {
		wait := options.Interval
		if remaining := options.Duration - elapsed; wait > remaining {
			wait = remaining
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-o.clock.After(wait):
		}
		elapsed += wait
		if err := capture(); err != nil {
			return nil, err
		}
	}
	result := make([]ObservedProcess, 0, len(observed))
	for _, entry := range observed {
		result = append(result, *entry)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Process.PID != result[j].Process.PID {
			return result[i].Process.PID < result[j].Process.PID
		}
		return result[i].Process.StartTime < result[j].Process.StartTime
	})
	return result, nil
}
