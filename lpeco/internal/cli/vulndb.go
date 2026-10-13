package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/orchestrator"
	"github.com/normalone/lpeco/internal/redact"
	"github.com/normalone/lpeco/internal/vulndb"
)

var syncVulnerabilityDatabase = vulndb.Sync

func resolveNewVulnerability(ctx context.Context, options VulnerabilityOptions, now time.Time) orchestrator.VulnerabilityInput {
	input := orchestrator.VulnerabilityInput{Mode: options.Mode, Explicit: options.SnapshotDir != ""}
	if input.Mode == "" {
		input.Mode = model.VulnerabilityModeAuto
	}
	if input.Mode == model.VulnerabilityModeOff {
		return input
	}
	if options.SnapshotDir != "" {
		snapshot, err := vulndb.LoadDirectory(ctx, options.SnapshotDir, now)
		input.Snapshot, input.LoadError = snapshotPointer(snapshot, err), err
		return input
	}
	databaseDirectory, err := vulnerabilityDatabaseDirectory(options.DatabaseDir)
	if err != nil {
		input.LoadError = err
		return input
	}
	snapshot, err := vulndb.LoadCurrent(ctx, databaseDirectory, now)
	input.Snapshot, input.LoadError = snapshotPointer(snapshot, err), err
	return input
}

func resolveResumeVulnerability(ctx context.Context, options VulnerabilityOptions, session model.Session, now time.Time) orchestrator.VulnerabilityInput {
	if session.SchemaVersion == 1 {
		return orchestrator.VulnerabilityInput{Mode: model.VulnerabilityModeOff}
	}
	mode := session.Vulnerability.Mode
	if mode == "" {
		mode = options.Mode
	}
	if mode == "" {
		mode = model.VulnerabilityModeAuto
	}
	input := orchestrator.VulnerabilityInput{Mode: mode, Explicit: options.SnapshotDir != ""}
	if mode == model.VulnerabilityModeOff {
		return input
	}
	if options.SnapshotDir != "" {
		snapshot, err := vulndb.LoadDirectory(ctx, options.SnapshotDir, now)
		input.Snapshot, input.LoadError = snapshotPointer(snapshot, err), err
		return input
	}
	databaseDirectory, err := vulnerabilityDatabaseDirectory(options.DatabaseDir)
	if err != nil {
		input.LoadError = err
		return input
	}
	pinnedDigest := session.Vulnerability.Snapshot.Digest
	var snapshot vulndb.Snapshot
	if pinnedDigest != "" {
		snapshot, err = vulndb.LoadDigest(ctx, databaseDirectory, pinnedDigest, now)
	} else {
		snapshot, err = vulndb.LoadCurrent(ctx, databaseDirectory, now)
	}
	input.Snapshot, input.LoadError = snapshotPointer(snapshot, err), err
	return input
}

func snapshotPointer(snapshot vulndb.Snapshot, err error) *vulndb.Snapshot {
	if err != nil {
		return nil
	}
	return &snapshot
}

func vulnerabilityDatabaseDirectory(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	return vulndb.DefaultDir()
}

func executeVulnerabilityDatabase(ctx context.Context, configuration Config, stdout, stderr io.Writer) int {
	switch configuration.Mode {
	case ModeVulnDBSync:
		reference, err := syncVulnerabilityDatabase(ctx, vulndb.SyncConfig{DatabaseDir: configuration.Vulnerability.DatabaseDir})
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "lpeco: vulnerability database sync: %s\n", redact.String(err.Error()))
			return ExitOperation
		}
		_, _ = fmt.Fprintf(stdout, "published vulnerability snapshot %s\n", reference.Digest)
		return ExitOK
	case ModeVulnDBStatus:
		if err := runVulnerabilityDatabaseStatus(ctx, configuration.Vulnerability, stdout, time.Now().UTC()); err != nil {
			_, _ = fmt.Fprintf(stderr, "lpeco: vulnerability database status: %s\n", redact.String(err.Error()))
			return ExitOperation
		}
		return ExitOK
	default:
		_, _ = fmt.Fprintln(stderr, "lpeco: unsupported vulnerability database command")
		return ExitUsage
	}
}

func runVulnerabilityDatabaseStatus(ctx context.Context, options VulnerabilityOptions, destination io.Writer, now time.Time) error {
	directory, err := vulnerabilityDatabaseDirectory(options.DatabaseDir)
	if err != nil {
		return err
	}
	snapshot, err := vulndb.LoadCurrent(ctx, directory, now)
	if err != nil {
		return err
	}
	if err := vulndb.Validate(snapshot); err != nil {
		return fmt.Errorf("validate current vulnerability snapshot: %w", err)
	}
	age := now.UTC().Sub(snapshot.Manifest.RetrievedAt.UTC())
	if age < 0 {
		age = 0
	}
	releases := append([]string(nil), snapshot.Manifest.SupportedReleases...)
	channels := append([]string(nil), snapshot.Manifest.SupportedChannels...)
	sort.Strings(releases)
	sort.Strings(channels)
	if _, err := fmt.Fprintf(destination,
		"integrity: valid\nprovider: %s\nschema: %d\ndigest: %s\nretrieved_at: %s\nage: %s\nstale: %t\nprovider_modified_at: %s\nsupported_releases: %s\nsupported_channels: %s\nadvisory_count: %d\nimpact_catalog_digest: %s\nsources:\n",
		snapshot.Manifest.Provider, snapshot.Manifest.SchemaVersion, snapshot.Manifest.Digest,
		snapshot.Manifest.RetrievedAt.UTC().Format(time.RFC3339), age.Round(time.Second), snapshot.Stale,
		formatStatusTime(snapshot.Manifest.MaxProviderModifiedAt), strings.Join(releases, ","), strings.Join(channels, ","),
		len(snapshot.Advisories), snapshot.Manifest.ImpactCatalogDigest,
	); err != nil {
		return err
	}
	for _, source := range snapshot.Manifest.Sources {
		if _, err := fmt.Fprintf(destination, "  - kind: %s url: %s provider_modified_at: %s\n", source.Kind, source.URL, formatStatusTime(source.ProviderModifiedAt)); err != nil {
			return err
		}
	}
	return nil
}

func formatStatusTime(value time.Time) string {
	if value.IsZero() {
		return "unknown"
	}
	return value.UTC().Format(time.RFC3339)
}
