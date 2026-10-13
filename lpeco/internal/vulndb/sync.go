package vulndb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/model"
)

const (
	// UbuntuOSVURL and UbuntuVEXURL are Canonical's complete public security
	// metadata archives. The CLI intentionally exposes no URL override.
	UbuntuOSVURL = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"
	UbuntuVEXURL = "https://security-metadata.canonical.com/vex/vex-all.tar.xz"

	canonicalMetadataHost = "security-metadata.canonical.com"
)

// SyncConfig contains injectable dependencies for deterministic local tests.
// Production callers normally provide only DatabaseDir.
type SyncConfig struct {
	DatabaseDir string
	HTTPClient  *http.Client
	OSVURL      string
	VEXURL      string
	Now         func() time.Time
	Limits      SyncLimits
}

type feedResult struct {
	notModified bool
	source      Source
	selected    int
}

// Sync retrieves both official Canonical archives, validates and normalizes
// them in memory, then atomically publishes one immutable snapshot. No current
// pointer is changed unless both sources and the resulting snapshot validate.
func Sync(ctx context.Context, configured SyncConfig) (model.SnapshotReference, error) {
	if err := ctx.Err(); err != nil {
		return model.SnapshotReference{}, err
	}
	config, err := resolveSyncConfig(configured)
	if err != nil {
		return model.SnapshotReference{}, err
	}
	now := config.Now().UTC()
	if now.IsZero() {
		return model.SnapshotReference{}, errors.New("synchronization clock returned the zero time")
	}

	current, hasCurrent, err := loadCurrentForSync(ctx, config.DatabaseDir, now)
	if err != nil {
		return model.SnapshotReference{}, err
	}
	policy, err := LoadUbuntuReleasePolicy()
	if err != nil {
		return model.SnapshotReference{}, err
	}
	annotations, _, err := LoadImpactCatalog()
	if err != nil {
		return model.SnapshotReference{}, err
	}
	normalizer := NewUbuntuNormalizer(policy, annotations)

	osv, err := syncFeed(ctx, config, "ubuntu-osv", config.OSVURL, priorSource(current, hasCurrent, "ubuntu-osv", config.OSVURL), func(name string, body io.Reader) error {
		if !selectedArchiveEntry(name, "osv/cve/") {
			return nil
		}
		return normalizer.AddOSV(name, body)
	})
	if err != nil {
		return model.SnapshotReference{}, fmt.Errorf("synchronize Ubuntu OSV feed: %w", err)
	}
	vex, err := syncFeed(ctx, config, "ubuntu-vex", config.VEXURL, priorSource(current, hasCurrent, "ubuntu-vex", config.VEXURL), func(name string, body io.Reader) error {
		if !selectedArchiveEntry(name, "vex/cve/") {
			return nil
		}
		return normalizer.AddVEX(name, body)
	})
	if err != nil {
		return model.SnapshotReference{}, fmt.Errorf("synchronize Ubuntu VEX feed: %w", err)
	}

	if osv.notModified || vex.notModified {
		if !osv.notModified || !vex.notModified || !hasCurrent {
			return model.SnapshotReference{}, errors.New("cannot reuse a partial or unvalidated not-modified response")
		}
		return snapshotReference(current, now), nil
	}
	if osv.selected == 0 || vex.selected == 0 {
		return model.SnapshotReference{}, errors.New("official feed archive contains no selected CVE records")
	}
	snapshot, err := normalizer.Snapshot(now, []Source{osv.source, vex.source})
	if err != nil {
		return model.SnapshotReference{}, fmt.Errorf("normalize synchronized feeds: %w", err)
	}
	return Publish(ctx, config.DatabaseDir, snapshot)
}

func resolveSyncConfig(config SyncConfig) (SyncConfig, error) {
	limits, err := resolveSyncLimits(config.Limits)
	if err != nil {
		return SyncConfig{}, err
	}
	config.Limits = limits
	if config.DatabaseDir == "" {
		config.DatabaseDir, err = DefaultDir()
		if err != nil {
			return SyncConfig{}, err
		}
	}
	if config.OSVURL == "" {
		config.OSVURL = UbuntuOSVURL
	}
	if config.VEXURL == "" {
		config.VEXURL = UbuntuVEXURL
	}
	for kind, raw := range map[string]string{"OSV": config.OSVURL, "VEX": config.VEXURL} {
		parsed, parseErr := url.Parse(raw)
		if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return SyncConfig{}, fmt.Errorf("invalid %s feed URL %q", kind, raw)
		}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	base := config.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: 15 * time.Minute}
	}
	client := *base
	previousRedirect := client.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != "https" || request.URL.Host != canonicalMetadataHost {
			return fmt.Errorf("redirect target %q is not the Canonical HTTPS metadata host", request.URL.String())
		}
		if previousRedirect != nil {
			return previousRedirect(request, via)
		}
		if len(via) >= 10 {
			return errors.New("redirect chain exceeds 10 requests")
		}
		return nil
	}
	config.HTTPClient = &client
	return config, nil
}

func loadCurrentForSync(ctx context.Context, root string, now time.Time) (Snapshot, bool, error) {
	snapshot, err := LoadCurrent(ctx, root, now)
	if err == nil {
		return snapshot, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, false, nil
	}
	return Snapshot{}, false, fmt.Errorf("load current vulnerability snapshot: %w", err)
}

func priorSource(snapshot Snapshot, available bool, kind, sourceURL string) *Source {
	if !available {
		return nil
	}
	for index := range snapshot.Manifest.Sources {
		source := &snapshot.Manifest.Sources[index]
		if source.Kind == kind && source.URL == sourceURL && source.SHA256 != "" && (source.ETag != "" || source.LastModified != "") {
			copy := *source
			return &copy
		}
	}
	return nil
}

func syncFeed(ctx context.Context, config SyncConfig, kind, sourceURL string, prior *Source, visit func(string, io.Reader) error) (feedResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return feedResult{}, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	if prior != nil {
		if prior.ETag != "" {
			request.Header.Set("If-None-Match", prior.ETag)
		}
		if prior.LastModified != "" {
			request.Header.Set("If-Modified-Since", prior.LastModified)
		}
	}
	response, err := config.HTTPClient.Do(request)
	if err != nil {
		return feedResult{}, err
	}
	if response.StatusCode == http.StatusNotModified {
		closeErr := response.Body.Close()
		if closeErr != nil {
			return feedResult{}, closeErr
		}
		if prior == nil {
			return feedResult{}, errors.New("received 304 without an exact validated prior source")
		}
		return feedResult{notModified: true, source: *prior}, nil
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return feedResult{}, fmt.Errorf("unexpected HTTP status %s", response.Status)
	}
	if response.ContentLength > config.Limits.MaxCompressedBytes {
		_ = response.Body.Close()
		return feedResult{}, fmt.Errorf("response Content-Length exceeds %d-byte compressed limit", config.Limits.MaxCompressedBytes)
	}

	hasher := sha256.New()
	selected := 0
	_, archiveErr := iterateXZTar(ctx, io.TeeReader(response.Body, hasher), config.Limits, func(name string, body io.Reader) error {
		if !selectedArchiveEntry(name, feedPrefix(kind)) {
			return nil
		}
		selected++
		return visit(name, body)
	})
	closeErr := response.Body.Close()
	if archiveErr != nil {
		return feedResult{}, archiveErr
	}
	if closeErr != nil {
		return feedResult{}, closeErr
	}

	lastModified := response.Header.Get("Last-Modified")
	var providerModified time.Time
	if lastModified != "" {
		providerModified, err = http.ParseTime(lastModified)
		if err != nil {
			return feedResult{}, fmt.Errorf("invalid Last-Modified header: %w", err)
		}
		providerModified = providerModified.UTC()
	}
	return feedResult{
		source: Source{
			Kind: kind, URL: sourceURL, ETag: response.Header.Get("ETag"), LastModified: lastModified,
			SHA256: hex.EncodeToString(hasher.Sum(nil)), ProviderModifiedAt: providerModified,
		},
		selected: selected,
	}, nil
}

func feedPrefix(kind string) string {
	if kind == "ubuntu-osv" {
		return "osv/cve/"
	}
	return "vex/cve/"
}

func selectedArchiveEntry(name, prefix string) bool {
	return strings.HasPrefix(name, prefix) && len(name) > len(prefix) && strings.HasSuffix(name, ".json")
}
