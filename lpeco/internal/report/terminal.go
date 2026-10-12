package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func WriteTerminal(destination io.Writer, data Data) error {
	writer := bufio.NewWriter(destination)
	if _, err := fmt.Fprintln(writer, "LPECO read-only privilege escalation candidates"); err != nil {
		return err
	}
	session := sanitizedSession(data.Session)
	if _, err := fmt.Fprintf(writer, "Session: %s (%s, transport %s)\n", session.ID, session.Status, session.TransportKind); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "Notice: Candidate ranking is a triage aid and does not prove successful privilege escalation."); err != nil {
		return err
	}
	candidates := sanitizedCandidates(data.Candidates)
	if len(candidates) == 0 {
		if _, err := fmt.Fprintln(writer, "\nNo evidence-backed privilege-boundary candidates were produced."); err != nil {
			return err
		}
	}
	for _, candidate := range candidates {
		if _, err := fmt.Fprintf(writer, "\n[%s] %s\n", candidate.Priority, candidate.RuleID); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "  confidence: %s | validation: %s | category: %s\n", candidate.Confidence, candidate.ValidationStatus, candidate.Category); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "  %s\n", candidate.Summary); err != nil {
			return err
		}
		line := fmt.Sprintf("  current: %s | target: %s", candidate.CurrentPrincipal.ID, candidate.TargetPrincipal.ID)
		if candidate.PrivilegedConsumer != nil {
			line += " | consumer: " + candidate.PrivilegedConsumer.ID
		}
		if candidate.ControlledObject != nil {
			line += " | object: " + candidate.ControlledObject.ID
		}
		if candidate.Trigger != nil {
			line += " | trigger: " + candidate.Trigger.ID
		}
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "  evidence: %s\n", listOrNone(candidate.EvidenceIDs)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "  missing facts: %s\n", listOrNone(candidate.MissingFacts)); err != nil {
			return err
		}
	}
	graphDiagnostics := sanitizedGraphDiagnostics(data.GraphDiagnostics)
	ruleDiagnostics := sanitizedRuleDiagnostics(data.RuleDiagnostics)
	if len(graphDiagnostics)+len(ruleDiagnostics) > 0 {
		if _, err := fmt.Fprintln(writer, "\nDiagnostics:"); err != nil {
			return err
		}
		for _, diagnostic := range graphDiagnostics {
			if _, err := fmt.Fprintf(writer, "- graph/%s: %s (evidence: %s)\n", diagnostic.Code, diagnostic.Message, listOrNone(diagnostic.EvidenceIDs)); err != nil {
				return err
			}
		}
		for _, diagnostic := range ruleDiagnostics {
			if _, err := fmt.Fprintf(writer, "- rule/%s/%s: %s (evidence: %s)\n", diagnostic.RuleID, diagnostic.Code, diagnostic.Message, listOrNone(diagnostic.EvidenceIDs)); err != nil {
				return err
			}
		}
	}
	limitations := sanitizedStrings(data.Limitations)
	if len(limitations) > 0 {
		if _, err := fmt.Fprintln(writer, "\nObservation limitations:"); err != nil {
			return err
		}
		for _, limitation := range limitations {
			if _, err := fmt.Fprintf(writer, "- %s\n", limitation); err != nil {
				return err
			}
		}
	}
	return writer.Flush()
}

func listOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}
