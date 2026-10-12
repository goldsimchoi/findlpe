package systemdunit

import (
	"bufio"
	"bytes"
	"strings"
)

type logicalLine struct {
	text string
	line int
}

func lexLogicalLines(content []byte) ([]logicalLine, []Diagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var lines []logicalLine
	var diagnostics []Diagnostic
	var continued strings.Builder
	startLine := 0
	physicalLine := 0
	for scanner.Scan() {
		physicalLine++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if continued.Len() > 0 && (trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";")) {
			continue
		}
		if continued.Len() == 0 {
			startLine = physicalLine
		}
		if hasContinuation(line) {
			piece := strings.TrimSpace(line[:len(line)-1])
			if piece != "" {
				if continued.Len() > 0 {
					continued.WriteByte(' ')
				}
				continued.WriteString(piece)
			}
			continue
		}
		if continued.Len() > 0 {
			piece := strings.TrimSpace(line)
			if piece != "" {
				continued.WriteByte(' ')
				continued.WriteString(piece)
			}
			lines = append(lines, logicalLine{text: continued.String(), line: startLine})
			continued.Reset()
			continue
		}
		lines = append(lines, logicalLine{text: line, line: physicalLine})
	}
	if scanner.Err() != nil {
		diagnostics = append(diagnostics, Diagnostic{Line: physicalLine, Code: "scanner-error", Message: scanner.Err().Error()})
	}
	if continued.Len() > 0 {
		lines = append(lines, logicalLine{text: continued.String(), line: startLine})
		diagnostics = append(diagnostics, Diagnostic{Line: startLine, Code: "trailing-continuation", Message: "file ends after a continuation"})
	}
	return lines, diagnostics
}

func hasContinuation(line string) bool {
	count := 0
	for index := len(line) - 1; index >= 0 && line[index] == '\\'; index-- {
		count++
	}
	return count%2 == 1
}
