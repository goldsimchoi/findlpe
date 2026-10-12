package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/model"
)

func TestStoreCreatesPrivateLayoutAndPersistsSession(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	store, err := Open(base, "session-one")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	want := model.Session{
		SchemaVersion: 1,
		ID:            "session-one",
		CreatedAt:     time.Unix(1_700_000_000, 0).UTC(),
		UpdatedAt:     time.Unix(1_700_000_000, 0).UTC(),
		Status:        model.SessionReady,
		TransportKind: "ssh",
		Checkpoint: model.Checkpoint{
			Phase:       "profile",
			Completed:   map[string]model.CompletedProbe{},
			RetryCounts: map[string]int{},
		},
	}
	if err := store.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	assertMode(t, filepath.Join(base, "session-one"), 0o700)
	assertMode(t, filepath.Join(base, "session-one", "evidence"), 0o700)
	assertMode(t, filepath.Join(base, "session-one", "session.json"), 0o600)

	got, err := store.Load(ctx, "session-one")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded session differs\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestPutEvidenceHashesAndDeduplicatesFingerprint(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	store, err := Open(base, "session-evidence")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := store.Create(ctx, model.Session{ID: "session-evidence", SchemaVersion: 1}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	input := model.Evidence{
		SessionID:        "session-evidence",
		ProbeID:          "identity.current",
		VariantID:        "proc-status",
		Adapter:          "ssh",
		InputFingerprint: "fingerprint-one",
		Status:           model.ProbeComplete,
	}
	body := []byte("uid=1000 gid=1000\n")
	got, deduplicated, err := store.PutEvidence(ctx, input, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("PutEvidence: %v", err)
	}
	if deduplicated {
		t.Fatal("first evidence write reported deduplicated")
	}
	wantDigest := sha256.Sum256(body)
	wantSHA := hex.EncodeToString(wantDigest[:])
	if got.SHA256 != wantSHA {
		t.Fatalf("SHA256 = %q, want %q", got.SHA256, wantSHA)
	}
	if got.ID == "" || got.RelativePath != filepath.ToSlash(filepath.Join("evidence", "identity.current-"+wantSHA+".txt")) {
		t.Fatalf("unexpected stored evidence metadata: %#v", got)
	}
	bodyPath := filepath.Join(base, "session-evidence", filepath.FromSlash(got.RelativePath))
	assertMode(t, bodyPath, 0o600)
	storedBody, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatalf("ReadFile evidence: %v", err)
	}
	if !bytes.Equal(storedBody, body) {
		t.Fatalf("evidence body = %q, want %q", storedBody, body)
	}

	second, deduplicated, err := store.PutEvidence(ctx, input, strings.NewReader("different output must not replace first"))
	if err != nil {
		t.Fatalf("deduplicated PutEvidence: %v", err)
	}
	if !deduplicated || second.ID != got.ID || second.SHA256 != got.SHA256 {
		t.Fatalf("dedup result = (%#v, %v), want original evidence", second, deduplicated)
	}
}

func TestFactsJSONLRoundTripAndRejectsTruncatedRecord(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	store, err := Open(base, "session-facts")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := store.Create(ctx, model.Session{ID: "session-facts", SchemaVersion: 1}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	want := []model.Fact{{
		ID:              "fact-one",
		Kind:            "identity",
		SourceCollector: "context",
		EvidenceIDs:     []string{"evidence-one"},
		Confidence:      model.ConfidenceHigh,
		Data:            []byte(`{"uid":1000}`),
	}}
	if err := store.AppendFacts(ctx, want); err != nil {
		t.Fatalf("AppendFacts: %v", err)
	}
	got, err := store.LoadFacts(ctx)
	if err != nil {
		t.Fatalf("LoadFacts: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("facts differ\ngot:  %#v\nwant: %#v", got, want)
	}
	assertMode(t, filepath.Join(base, "session-facts", "facts.jsonl"), 0o600)

	invalid, err := os.ReadFile("testdata/legacy-or-invalid-session.json")
	if err != nil {
		t.Fatalf("read malformed fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(base, "session-facts", "facts.jsonl"), invalid, 0o600); err != nil {
		t.Fatalf("install malformed fixture: %v", err)
	}
	if _, err := store.LoadFacts(ctx); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("LoadFacts malformed error = %v, want line 2", err)
	}
}

func TestCandidatesAndCheckpointReplaceAtomically(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	store, err := Open(base, "session-state")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := store.Create(ctx, model.Session{ID: "session-state", SchemaVersion: 1}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	first := []model.Candidate{{
		ID:               "candidate-one",
		RuleID:           "rule-one",
		Category:         "systemd",
		Priority:         model.PriorityP2,
		Confidence:       model.ConfidenceMedium,
		CurrentPrincipal: model.NodeRef{ID: "principal:1000", Kind: model.NodePrincipal},
		TargetPrincipal:  model.NodeRef{ID: "principal:0", Kind: model.NodePrincipal},
		EvidenceIDs:      []string{"evidence-one"},
		ValidationStatus: model.ValidationIncomplete,
		Summary:          "candidate one",
	}}
	if err := store.SaveCandidates(ctx, first); err != nil {
		t.Fatalf("SaveCandidates first: %v", err)
	}
	second := append([]model.Candidate(nil), first...)
	second[0].Summary = "replacement candidate"
	if err := store.SaveCandidates(ctx, second); err != nil {
		t.Fatalf("SaveCandidates second: %v", err)
	}
	got, err := store.LoadCandidates(ctx)
	if err != nil {
		t.Fatalf("LoadCandidates: %v", err)
	}
	if !reflect.DeepEqual(got, second) {
		t.Fatalf("candidates differ\ngot:  %#v\nwant: %#v", got, second)
	}
	assertMode(t, filepath.Join(base, "session-state", "candidates.json"), 0o600)

	checkpoint := model.Checkpoint{
		Phase: "primary",
		Completed: map[string]model.CompletedProbe{
			"process.snapshot|abc": {ProbeID: "process.snapshot", InputFingerprint: "abc", Status: model.ProbeComplete},
		},
		RetryCounts:       map[string]int{"process.snapshot|abc": 1},
		PendingValidation: []string{"path:/opt/demo"},
		UpdatedAt:         time.Unix(1_700_000_100, 0).UTC(),
	}
	if err := store.SaveCheckpoint(ctx, checkpoint); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
	session, err := store.Load(ctx, "session-state")
	if err != nil {
		t.Fatalf("Load after checkpoint: %v", err)
	}
	if !reflect.DeepEqual(session.Checkpoint, checkpoint) {
		t.Fatalf("checkpoint differs\ngot:  %#v\nwant: %#v", session.Checkpoint, checkpoint)
	}

	entries, err := os.ReadDir(filepath.Join(base, "session-state"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("atomic write left temporary file %q", entry.Name())
		}
	}
}

func TestDefaultStateDirUsesXDGThenHomeFallback(t *testing.T) {
	t.Run("XDG", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", "/tmp/lpeco-state")
		got, err := DefaultStateDir()
		if err != nil {
			t.Fatalf("DefaultStateDir: %v", err)
		}
		if got != "/tmp/lpeco-state/lpeco/sessions" {
			t.Fatalf("state dir = %q", got)
		}
	})

	t.Run("home fallback", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", "")
		t.Setenv("HOME", "/tmp/lpeco-home")
		got, err := DefaultStateDir()
		if err != nil {
			t.Fatalf("DefaultStateDir: %v", err)
		}
		if got != "/tmp/lpeco-home/.local/state/lpeco/sessions" {
			t.Fatalf("state dir = %q", got)
		}
	})
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode %s = %#o, want %#o", path, got, want)
	}
}
