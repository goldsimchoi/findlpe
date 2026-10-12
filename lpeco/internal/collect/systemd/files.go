package systemd

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"

	"github.com/normalone/lpeco/internal/systemdunit"
)

type DocumentSet struct {
	Documents []systemdunit.Document
	Complete  bool
}

func ParseCat(unitName string, input []byte, evidenceID string) ([]systemdunit.Document, []CollectorDiagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var documents []systemdunit.Document
	var diagnostics []CollectorDiagnostic
	var path string
	var content strings.Builder
	flush := func() {
		if path == "" {
			return
		}
		document, parseDiagnostics := systemdunit.Parse(systemdunit.Source{Path: path, EvidenceID: evidenceID, Content: []byte(content.String())})
		documents = append(documents, document)
		for _, diagnostic := range parseDiagnostics {
			diagnostics = append(diagnostics, CollectorDiagnostic{Code: "unit-" + diagnostic.Code, Message: diagnostic.Message, UnitName: unitName, EvidenceIDs: []string{evidenceID}})
		}
		content.Reset()
	}
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.HasPrefix(line, "# /") {
			flush()
			path = strings.TrimSpace(strings.TrimPrefix(line, "# "))
			continue
		}
		if path != "" {
			content.WriteString(line)
			content.WriteByte('\n')
		}
	}
	flush()
	if scanner.Err() != nil {
		diagnostics = append(diagnostics, CollectorDiagnostic{Code: "cat-read-error", Message: scanner.Err().Error(), UnitName: unitName, EvidenceIDs: []string{evidenceID}})
	}
	if len(documents) == 0 {
		diagnostics = append(diagnostics, CollectorDiagnostic{Code: "cat-no-sources", Message: "no source headers found", UnitName: unitName, EvidenceIDs: []string{evidenceID}})
	}
	for index := range documents {
		if filepath.Base(documents[index].Source.Path) == unitName || strings.HasSuffix(filepath.Base(filepath.Dir(documents[index].Source.Path)), ".d") {
			continue
		}
		diagnostics = append(diagnostics, CollectorDiagnostic{Code: "unexpected-unit-source", Message: documents[index].Source.Path, UnitName: unitName, EvidenceIDs: []string{evidenceID}})
	}
	return documents, diagnostics
}
