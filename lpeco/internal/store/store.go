package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/normalone/lpeco/internal/model"
)

type SessionStore interface {
	Create(context.Context, model.Session) error
	Load(context.Context, string) (model.Session, error)
	PutEvidence(context.Context, model.Evidence, io.Reader) (model.Evidence, bool, error)
	ListEvidence(context.Context) ([]model.Evidence, error)
	AppendFacts(context.Context, []model.Fact) error
	LoadFacts(context.Context) ([]model.Fact, error)
	SaveCandidates(context.Context, []model.Candidate) error
	LoadCandidates(context.Context) ([]model.Candidate, error)
	SaveCheckpoint(context.Context, model.Checkpoint) error
}

type Store struct {
	mu              sync.Mutex
	layout          layout
	sessionID       string
	evidenceLoaded  bool
	evidenceByInput map[string]model.Evidence
}

var _ SessionStore = (*Store)(nil)

func Open(baseDir, sessionID string) (*Store, error) {
	paths, err := newLayout(baseDir, sessionID)
	if err != nil {
		return nil, err
	}
	return &Store{
		layout:          paths,
		sessionID:       sessionID,
		evidenceByInput: make(map[string]model.Evidence),
	}, nil
}

func (s *Store) Create(ctx context.Context, session model.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if session.ID != s.sessionID {
		return fmt.Errorf("session ID %q does not match store %q", session.ID, s.sessionID)
	}
	if _, err := os.Stat(s.layout.session); err == nil {
		return fmt.Errorf("session %q already exists", s.sessionID)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect session: %w", err)
	}
	if err := os.MkdirAll(s.layout.evidence, 0o700); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}
	if err := os.Chmod(s.layout.root, 0o700); err != nil {
		return fmt.Errorf("restrict session directory: %w", err)
	}
	if err := os.Chmod(s.layout.evidence, 0o700); err != nil {
		return fmt.Errorf("restrict evidence directory: %w", err)
	}
	if session.SchemaVersion == 0 {
		session.SchemaVersion = 1
	}
	if err := writeJSONAtomic(ctx, s.layout.session, session); err != nil {
		return err
	}
	if err := writePrivateFile(ctx, s.layout.facts, nil); err != nil {
		return err
	}
	if err := writeJSONAtomic(ctx, s.layout.candidates, []model.Candidate{}); err != nil {
		return err
	}
	s.evidenceLoaded = true
	return nil
}

func (s *Store) Load(ctx context.Context, sessionID string) (model.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sessionID != s.sessionID {
		return model.Session{}, fmt.Errorf("session ID %q does not match store %q", sessionID, s.sessionID)
	}
	return s.loadSessionLocked(ctx)
}

func (s *Store) loadSessionLocked(ctx context.Context) (model.Session, error) {
	if err := ctx.Err(); err != nil {
		return model.Session{}, err
	}
	var session model.Session
	if err := readJSON(s.layout.session, &session); err != nil {
		return model.Session{}, fmt.Errorf("load session %q: %w", s.sessionID, err)
	}
	if session.ID != s.sessionID {
		return model.Session{}, fmt.Errorf("session metadata ID %q does not match directory %q", session.ID, s.sessionID)
	}
	return session, nil
}

func (s *Store) PutEvidence(ctx context.Context, evidence model.Evidence, body io.Reader) (model.Evidence, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return model.Evidence{}, false, err
	}
	if evidence.SessionID != s.sessionID {
		return model.Evidence{}, false, fmt.Errorf("evidence session ID %q does not match store %q", evidence.SessionID, s.sessionID)
	}
	if evidence.ProbeID == "" || evidence.InputFingerprint == "" {
		return model.Evidence{}, false, errors.New("evidence probe ID and input fingerprint are required")
	}
	if body == nil {
		return model.Evidence{}, false, errors.New("evidence body is required")
	}
	if err := s.loadEvidenceIndexLocked(ctx); err != nil {
		return model.Evidence{}, false, err
	}
	key := evidenceKey(evidence.SessionID, evidence.ProbeID, evidence.InputFingerprint)
	if existing, ok := s.evidenceByInput[key]; ok {
		return existing, true, nil
	}

	temporary, err := os.CreateTemp(s.layout.evidence, ".body.tmp-")
	if err != nil {
		return model.Evidence{}, false, fmt.Errorf("create evidence temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	keepTemporary := false
	defer func() {
		if !keepTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return model.Evidence{}, false, fmt.Errorf("restrict evidence temporary file: %w", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(temporary, hasher), &contextReader{ctx: ctx, reader: body}); err != nil {
		temporary.Close()
		return model.Evidence{}, false, fmt.Errorf("write evidence body: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return model.Evidence{}, false, fmt.Errorf("sync evidence body: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return model.Evidence{}, false, fmt.Errorf("close evidence body: %w", err)
	}

	evidence.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	evidence.RelativePath = filepath.ToSlash(filepath.Join("evidence", safeProbeID(evidence.ProbeID)+"-"+evidence.SHA256+".txt"))
	evidence.ID, err = model.StableID("evidence", struct {
		SessionID, ProbeID, InputFingerprint, SHA256 string
	}{evidence.SessionID, evidence.ProbeID, evidence.InputFingerprint, evidence.SHA256})
	if err != nil {
		return model.Evidence{}, false, err
	}
	finalBody := filepath.Join(s.layout.root, filepath.FromSlash(evidence.RelativePath))
	if _, err := os.Stat(finalBody); os.IsNotExist(err) {
		if err := os.Rename(temporaryPath, finalBody); err != nil {
			return model.Evidence{}, false, fmt.Errorf("commit evidence body: %w", err)
		}
		keepTemporary = true
	} else if err != nil {
		return model.Evidence{}, false, fmt.Errorf("inspect evidence body: %w", err)
	}
	if err := os.Chmod(finalBody, 0o600); err != nil {
		return model.Evidence{}, false, fmt.Errorf("restrict evidence body: %w", err)
	}
	metadataPath := strings.TrimSuffix(finalBody, ".txt") + ".json"
	if err := writeJSONAtomic(ctx, metadataPath, evidence); err != nil {
		return model.Evidence{}, false, fmt.Errorf("write evidence metadata: %w", err)
	}
	s.evidenceByInput[key] = evidence
	return evidence, false, nil
}

func (s *Store) ListEvidence(ctx context.Context) ([]model.Evidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadEvidenceIndexLocked(ctx); err != nil {
		return nil, err
	}
	result := make([]model.Evidence, 0, len(s.evidenceByInput))
	for _, evidence := range s.evidenceByInput {
		result = append(result, evidence)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (s *Store) loadEvidenceIndexLocked(ctx context.Context) error {
	if s.evidenceLoaded {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.layout.evidence)
	if err != nil {
		return fmt.Errorf("read evidence directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var evidence model.Evidence
		if err := readJSON(filepath.Join(s.layout.evidence, entry.Name()), &evidence); err != nil {
			return fmt.Errorf("load evidence metadata %q: %w", entry.Name(), err)
		}
		key := evidenceKey(evidence.SessionID, evidence.ProbeID, evidence.InputFingerprint)
		s.evidenceByInput[key] = evidence
	}
	s.evidenceLoaded = true
	return nil
}

func evidenceKey(sessionID, probeID, fingerprint string) string {
	return sessionID + "\x00" + probeID + "\x00" + fingerprint
}

func (s *Store) AppendFacts(ctx context.Context, facts []model.Fact) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return appendFacts(ctx, s.layout.facts, facts)
}

func (s *Store) LoadFacts(ctx context.Context) ([]model.Fact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return loadFacts(ctx, s.layout.facts)
}

func (s *Store) SaveCandidates(ctx context.Context, candidates []model.Candidate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, candidate := range candidates {
		if err := candidate.Validate(); err != nil {
			return fmt.Errorf("validate candidate %d: %w", i, err)
		}
	}
	return writeJSONAtomic(ctx, s.layout.candidates, candidates)
}

func (s *Store) LoadCandidates(ctx context.Context) ([]model.Candidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var candidates []model.Candidate
	if err := readJSON(s.layout.candidates, &candidates); err != nil {
		if os.IsNotExist(err) {
			return []model.Candidate{}, nil
		}
		return nil, fmt.Errorf("load candidates: %w", err)
	}
	if candidates == nil {
		candidates = []model.Candidate{}
	}
	return candidates, nil
}

func (s *Store) SaveCheckpoint(ctx context.Context, checkpoint model.Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, err := s.loadSessionLocked(ctx)
	if err != nil {
		return err
	}
	session.Checkpoint = checkpoint
	if checkpoint.UpdatedAt.IsZero() {
		session.UpdatedAt = time.Now().UTC()
	} else {
		session.UpdatedAt = checkpoint.UpdatedAt
	}
	return writeJSONAtomic(ctx, s.layout.session, session)
}

func readJSON(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func writeJSONAtomic(ctx context.Context, path string, value any) error {
	var encoded strings.Builder
	encoder := json.NewEncoder(&encoded)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	return writePrivateFile(ctx, path, strings.NewReader(encoded.String()))
}

func writePrivateFile(ctx context.Context, path string, body io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temporary %s: %w", filepath.Base(path), err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("restrict temporary %s: %w", filepath.Base(path), err)
	}
	if body != nil {
		if _, err := io.Copy(temporary, &contextReader{ctx: ctx, reader: body}); err != nil {
			temporary.Close()
			return fmt.Errorf("write temporary %s: %w", filepath.Base(path), err)
		}
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary %s: %w", filepath.Base(path), err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	committed = true
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict %s: %w", filepath.Base(path), err)
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
