package orchestrator

import (
	"context"
	"fmt"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/store"
)

func Resume(ctx context.Context, transport adapter.Adapter, sessionStore store.SessionStore, options Options) (Result, error) {
	if options.ProcessObservation < 0 {
		return Result{}, fmt.Errorf("process observation duration cannot be negative")
	}
	options = normalizeOptions(options)
	if options.SessionID == "" {
		return Result{}, fmt.Errorf("session ID is required")
	}
	session, err := sessionStore.Load(ctx, options.SessionID)
	if err != nil {
		return Result{}, fmt.Errorf("load session: %w", err)
	}
	facts, err := sessionStore.LoadFacts(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("load facts: %w", err)
	}
	return run(ctx, transport, sessionStore, options, session, facts)
}
