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
	if session.SchemaVersion == 1 {
		options.Vulnerability = VulnerabilityInput{Mode: "off"}
	} else {
		if session.Vulnerability.Mode != "" {
			options.Vulnerability.Mode = session.Vulnerability.Mode
		}
		pin := session.Vulnerability.Snapshot
		if pin.Digest != "" && options.Vulnerability.Mode != "off" {
			snapshot := options.Vulnerability.Snapshot
			switch {
			case options.Vulnerability.LoadError != nil:
				options.Vulnerability.Snapshot = nil
			case snapshot == nil:
				options.Vulnerability.LoadError = fmt.Errorf("pinned vulnerability snapshot %s is unavailable", pin.Digest)
			case snapshot.Manifest.Provider != pin.Provider:
				options.Vulnerability.LoadError = pinnedSnapshotMismatch("provider", pin.Provider, snapshot.Manifest.Provider)
			case snapshot.Manifest.SchemaVersion != pin.SchemaVersion:
				options.Vulnerability.LoadError = pinnedSnapshotMismatch("schema", pin.SchemaVersion, snapshot.Manifest.SchemaVersion)
			case snapshot.Manifest.Digest != pin.Digest:
				options.Vulnerability.LoadError = pinnedSnapshotMismatch("digest", pin.Digest, snapshot.Manifest.Digest)
			case snapshot.Manifest.ImpactCatalogDigest != pin.ImpactCatalogDigest:
				options.Vulnerability.LoadError = pinnedSnapshotMismatch("impact catalog digest", pin.ImpactCatalogDigest, snapshot.Manifest.ImpactCatalogDigest)
			}
			if options.Vulnerability.LoadError != nil {
				options.Vulnerability.Snapshot = nil
			}
		}
	}
	return run(ctx, transport, sessionStore, options, session, facts)
}

func pinnedSnapshotMismatch(field string, wanted, got any) error {
	return fmt.Errorf("pinned vulnerability snapshot %s mismatch: want %v, got %v", field, wanted, got)
}
