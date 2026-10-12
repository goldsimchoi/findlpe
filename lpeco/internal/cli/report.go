package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/normalone/lpeco/internal/report"
	"github.com/normalone/lpeco/internal/store"
)

var defaultLimitations = []string{
	"Candidate ranking does not prove successful privilege escalation.",
	"Read-only observations can be incomplete when permissions deny access or processes exit during collection.",
}

func runReport(ctx context.Context, configuration Config, destination io.Writer) error {
	sessionStore, err := store.Open(configuration.Common.StateDir, configuration.ResumeSessionID)
	if err != nil {
		return err
	}
	return writeStoredReport(ctx, sessionStore, configuration.ResumeSessionID, configuration.Report.Format, destination)
}

func writeStoredReport(ctx context.Context, sessionStore *store.Store, sessionID, format string, destination io.Writer) error {
	session, err := sessionStore.Load(ctx, sessionID)
	if err != nil {
		return err
	}
	facts, err := sessionStore.LoadFacts(ctx)
	if err != nil {
		return err
	}
	candidates, err := sessionStore.LoadCandidates(ctx)
	if err != nil {
		return err
	}
	evidence, err := sessionStore.ListEvidence(ctx)
	if err != nil {
		return err
	}
	data := report.Data{Session: session, Facts: facts, Candidates: candidates, Evidence: evidence, Limitations: defaultLimitations}
	switch format {
	case "", "terminal":
		return report.WriteTerminal(destination, data)
	case "json":
		return report.WriteJSON(destination, data)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}
