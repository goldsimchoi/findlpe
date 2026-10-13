package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/redact"
)

func WriteTerminal(destination io.Writer, data Data) error {
	writer := bufio.NewWriter(destination)
	if _, err := fmt.Fprintln(writer, "LPECO read-only privilege escalation candidates"); err != nil {
		return err
	}
	session := sanitizedSession(data.Session)
	if _, err := fmt.Fprintf(writer, "Session: %s (%s, transport %s)\n", terminal(session.ID), terminal(string(session.Status)), terminal(session.TransportKind)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "Notice: Candidate ranking is a triage aid and does not prove successful privilege escalation."); err != nil {
		return err
	}

	candidates := sanitizedCandidates(data.Candidates)
	var deterministic, knownPaths []model.Candidate
	for _, candidate := range candidates {
		if candidate.Category == "known-vulnerability" {
			knownPaths = append(knownPaths, candidate)
		} else {
			deterministic = append(deterministic, candidate)
		}
	}
	known := buildKnownVulnerabilities(data)
	matchesByID := make(map[string]model.VulnerabilityMatch, len(known.Matches))
	for _, match := range known.Matches {
		matchesByID[match.ID] = match
	}

	if _, err := fmt.Fprintln(writer, "\nDeterministic candidates:"); err != nil {
		return err
	}
	if len(deterministic) == 0 {
		if _, err := fmt.Fprintln(writer, "None."); err != nil {
			return err
		}
	}
	for _, candidate := range deterministic {
		if err := writeCandidate(writer, candidate, nil); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(writer, "\nKnown-vulnerability path candidates:"); err != nil {
		return err
	}
	if len(knownPaths) == 0 {
		if _, err := fmt.Fprintln(writer, "None."); err != nil {
			return err
		}
	}
	for _, candidate := range knownPaths {
		var related []model.VulnerabilityMatch
		for _, id := range candidate.RelatedMatchIDs {
			if match, ok := matchesByID[id]; ok {
				related = append(related, match)
			}
		}
		if err := writeCandidate(writer, candidate, related); err != nil {
			return err
		}
	}

	relatedMatchIDs := make(map[string]bool)
	for _, candidate := range knownPaths {
		for _, id := range candidate.RelatedMatchIDs {
			relatedMatchIDs[id] = true
		}
	}
	var matchOnly []model.VulnerabilityMatch
	fixed, notAffected, affected := 0, 0, 0
	for _, match := range known.Matches {
		switch match.State {
		case model.VulnerabilityStateAffected:
			affected++
		case model.VulnerabilityStateFixed:
			fixed++
		case model.VulnerabilityStateNotAffected:
			notAffected++
		}
		if !relatedMatchIDs[match.ID] && (match.State == model.VulnerabilityStateAffected || match.State == model.VulnerabilityStateUnknown) {
			matchOnly = append(matchOnly, match)
		}
	}
	if _, err := fmt.Fprintln(writer, "\nMatch-only known-vulnerability inventory:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Summary counts: fixed: %d | not affected: %d\n", fixed, notAffected); err != nil {
		return err
	}
	if len(matchOnly) == 0 {
		if _, err := fmt.Fprintln(writer, "Affected/unknown match-only records: none."); err != nil {
			return err
		}
	} else {
		for _, match := range matchOnly {
			if err := writeMatch(writer, match, ""); err != nil {
				return err
			}
		}
	}
	if affected == 0 && known.Coverage.Status == model.VulnerabilityCoverageComplete {
		if _, err := fmt.Fprintf(writer, "No affected records matched the selected privileged-component scope in snapshot %s.\n", terminal(known.Coverage.Snapshot.Digest)); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(writer, "\nKnown-vulnerability coverage:"); err != nil {
		return err
	}
	if err := writeCoverage(writer, known); err != nil {
		return err
	}

	graphDiagnostics := sanitizedGraphDiagnostics(data.GraphDiagnostics)
	ruleDiagnostics := sanitizedRuleDiagnostics(data.RuleDiagnostics)
	if len(graphDiagnostics)+len(ruleDiagnostics) > 0 {
		if _, err := fmt.Fprintln(writer, "\nDiagnostics:"); err != nil {
			return err
		}
		for _, diagnostic := range graphDiagnostics {
			if _, err := fmt.Fprintf(writer, "- graph/%s: %s (evidence: %s)\n", terminal(diagnostic.Code), terminal(diagnostic.Message), listOrNone(diagnostic.EvidenceIDs)); err != nil {
				return err
			}
		}
		for _, diagnostic := range ruleDiagnostics {
			if _, err := fmt.Fprintf(writer, "- rule/%s/%s: %s (evidence: %s)\n", terminal(diagnostic.RuleID), terminal(diagnostic.Code), terminal(diagnostic.Message), listOrNone(diagnostic.EvidenceIDs)); err != nil {
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
			if _, err := fmt.Fprintf(writer, "- %s\n", terminal(limitation)); err != nil {
				return err
			}
		}
	}
	return writer.Flush()
}

func writeCandidate(writer io.Writer, candidate model.Candidate, related []model.VulnerabilityMatch) error {
	if _, err := fmt.Fprintf(writer, "\n[%s] %s\n", terminal(string(candidate.Priority)), terminal(candidate.RuleID)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "  confidence: %s | validation: %s | category: %s\n", terminal(string(candidate.Confidence)), terminal(string(candidate.ValidationStatus)), terminal(candidate.Category)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "  %s\n", terminal(candidate.Summary)); err != nil {
		return err
	}
	line := fmt.Sprintf("  current: %s | target: %s", terminal(candidate.CurrentPrincipal.ID), terminal(candidate.TargetPrincipal.ID))
	if candidate.PrivilegedConsumer != nil {
		line += " | consumer: " + terminal(candidate.PrivilegedConsumer.ID)
	}
	if candidate.ControlledObject != nil {
		line += " | object: " + terminal(candidate.ControlledObject.ID)
	}
	if candidate.Trigger != nil {
		line += " | trigger: " + terminal(candidate.Trigger.ID)
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
	if len(candidate.RelatedMatchIDs) > 0 {
		if _, err := fmt.Fprintf(writer, "  related match IDs: %s\n", listOrNone(candidate.RelatedMatchIDs)); err != nil {
			return err
		}
	}
	for _, match := range related {
		if err := writeMatch(writer, match, "  "); err != nil {
			return err
		}
	}
	return nil
}

func writeMatch(writer io.Writer, match model.VulnerabilityMatch, indent string) error {
	if _, err := fmt.Fprintf(writer, "%s\n%s[%s] %s (%s)\n", indent, indent, terminal(strings.ToUpper(string(match.State))), terminal(match.ID), terminal(match.AdvisoryID)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "%s  binary: %s:%s %s | source: %s %s\n", indent, terminal(match.BinaryPackage), terminal(match.BinaryArchitecture), terminal(match.BinaryVersion.Raw), terminal(match.SourcePackage), terminal(match.SourceVersion.Raw)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "%s  reason: %s | snapshot: %s | kernel: %t\n", indent, terminal(match.Reason), terminal(match.SnapshotDigest), match.Kernel); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "%s  CVEs: %s | USNs: %s | annotations: %s\n", indent, listOrNone(match.CVEIDs), listOrNone(match.USNIDs), listOrNone(match.ImpactAnnotationIDs)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "%s  references: %s\n", indent, listOrNone(match.OfficialReferences)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "%s  evidence: %s | missing facts: %s | confidence: %s\n", indent, listOrNone(match.TargetEvidenceIDs), listOrNone(match.MissingFacts), terminal(string(match.Confidence))); err != nil {
		return err
	}
	return nil
}

func writeCoverage(writer io.Writer, known KnownVulnerabilities) error {
	coverage := known.Coverage
	if _, err := fmt.Fprintf(writer, "  mode: %s | status: %s | provider: %s\n", terminal(string(coverage.Mode)), terminal(string(coverage.Status)), valueOrNone(coverage.Provider)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "  target: release=%s codename=%s channel=%s architecture=%s\n", valueOrNone(coverage.SelectedRelease), valueOrNone(coverage.SelectedCodename), valueOrNone(coverage.SelectedChannel), valueOrNone(coverage.SelectedArchitecture)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "  snapshot: %s | schema: %d | stale: %t | retrieved: %s | provider modified: %s\n",
		valueOrNone(coverage.Snapshot.Digest), coverage.Snapshot.SchemaVersion, coverage.Snapshot.Stale, timeOrNone(coverage.Snapshot.RetrievedAt), timeOrNone(coverage.Snapshot.ProviderModifiedAt)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "  supported releases: %s | channels: %s | impact catalog: %s\n",
		listOrNone(coverage.Snapshot.SupportedReleases), listOrNone(coverage.Snapshot.SupportedChannels), valueOrNone(coverage.Snapshot.ImpactCatalogDigest)); err != nil {
		return err
	}
	if len(known.Diagnostics) == 0 {
		_, err := fmt.Fprintln(writer, "  diagnostics: none")
		return err
	}
	if _, err := fmt.Fprintln(writer, "  diagnostics:"); err != nil {
		return err
	}
	for _, diagnostic := range known.Diagnostics {
		if _, err := fmt.Fprintf(writer, "  - %s: %s (match: %s; evidence: %s; missing: %s)\n",
			terminal(diagnostic.Code), terminal(diagnostic.Message), valueOrNone(diagnostic.MatchID), listOrNone(diagnostic.EvidenceIDs), listOrNone(diagnostic.MissingFacts)); err != nil {
			return err
		}
	}
	return nil
}

func terminal(value string) string { return redact.TerminalString(value) }

func valueOrNone(value string) string {
	if value == "" {
		return "none"
	}
	return terminal(value)
}

func timeOrNone(value time.Time) string {
	if value.IsZero() {
		return "none"
	}
	return terminal(value.UTC().Format(time.RFC3339))
}

func listOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	escaped := make([]string, len(values))
	for index, value := range values {
		escaped[index] = terminal(value)
	}
	return strings.Join(escaped, ", ")
}
