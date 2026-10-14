package systemd

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/normalone/lpeco/internal/systemdunit"
)

const catFrameHeader = "LPECO_SYSTEMD_CAT_V2\n"

type DocumentSet struct {
	Documents []systemdunit.Document
	Complete  bool
}

// ParseCat decodes length-delimited unit sources emitted by the collector.
// Source paths are hexadecimal and each content length is explicit, so a legal
// unit comment can never be confused with provenance framing.
func ParseCat(unitName string, input []byte, evidenceID string) ([]systemdunit.Document, []CollectorDiagnostic) {
	payload := input
	if bytes.HasPrefix(payload, []byte("LPECO_MANAGER\t")) {
		newline := bytes.IndexByte(payload, '\n')
		if newline < 0 {
			return nil, []CollectorDiagnostic{catDiagnostic("cat-invalid-manager-frame", "manager frame is truncated", unitName, evidenceID)}
		}
		payload = payload[newline+1:]
	}
	if !bytes.HasPrefix(payload, []byte(catFrameHeader)) {
		return nil, []CollectorDiagnostic{catDiagnostic("cat-unsupported-format", "length-delimited source frame is missing", unitName, evidenceID)}
	}
	payload = payload[len(catFrameHeader):]

	var documents []systemdunit.Document
	var diagnostics []CollectorDiagnostic
	seenPaths := make(map[string]bool)
	ended := false
	for len(payload) > 0 {
		if bytes.HasPrefix(payload, []byte("END\n")) {
			ended = true
			payload = payload[len("END\n"):]
			if len(bytes.TrimSpace(payload)) > 0 {
				diagnostics = append(diagnostics, catDiagnostic("cat-trailing-data", "data follows the end of the source frame", unitName, evidenceID))
			}
			break
		}

		newline := bytes.IndexByte(payload, '\n')
		if newline < 0 {
			diagnostics = append(diagnostics, catDiagnostic("cat-truncated-header", "source header is truncated", unitName, evidenceID))
			break
		}
		header := string(payload[:newline])
		payload = payload[newline+1:]
		fields := strings.Split(header, "\t")
		if len(fields) != 3 || fields[0] != "SOURCE" {
			diagnostics = append(diagnostics, catDiagnostic("cat-invalid-source-header", "source header is malformed", unitName, evidenceID))
			break
		}
		pathBytes, err := hex.DecodeString(fields[1])
		if err != nil {
			diagnostics = append(diagnostics, catDiagnostic("cat-invalid-source-path", "source path encoding is malformed", unitName, evidenceID))
			break
		}
		contentLength, err := strconv.ParseUint(fields[2], 10, 63)
		if err != nil {
			diagnostics = append(diagnostics, catDiagnostic("cat-invalid-source-length", "source content length is malformed", unitName, evidenceID))
			break
		}
		if contentLength > uint64(len(payload)) {
			diagnostics = append(diagnostics, catDiagnostic("cat-truncated-source", "source content is truncated", unitName, evidenceID))
			break
		}
		content := append([]byte(nil), payload[:int(contentLength)]...)
		payload = payload[int(contentLength):]
		path := string(pathBytes)
		if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
			diagnostics = append(diagnostics, catDiagnostic("cat-invalid-source-path", "source path is not an absolute filesystem path", unitName, evidenceID))
			continue
		}
		if seenPaths[path] {
			diagnostics = append(diagnostics, catDiagnostic("cat-duplicate-source", path, unitName, evidenceID))
			continue
		}
		seenPaths[path] = true
		document, parseDiagnostics := systemdunit.Parse(systemdunit.Source{Path: path, EvidenceID: evidenceID, Content: content})
		documents = append(documents, document)
		for _, diagnostic := range parseDiagnostics {
			diagnostics = append(diagnostics, catDiagnostic("unit-"+diagnostic.Code, diagnostic.Message, unitName, evidenceID))
		}
	}
	if !ended {
		diagnostics = append(diagnostics, catDiagnostic("cat-missing-end", "source frame has no end marker", unitName, evidenceID))
	}
	if len(documents) == 0 {
		diagnostics = append(diagnostics, catDiagnostic("cat-no-sources", "no framed unit sources found", unitName, evidenceID))
	}
	return documents, diagnostics
}

func catDiagnostic(code, message, unitName, evidenceID string) CollectorDiagnostic {
	return CollectorDiagnostic{Code: code, Message: message, UnitName: unitName, EvidenceIDs: []string{evidenceID}}
}
