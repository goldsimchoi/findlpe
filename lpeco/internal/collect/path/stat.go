package path

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

type ObservationStatus string

const (
	ObservationComplete    ObservationStatus = "complete"
	ObservationUnavailable ObservationStatus = "unavailable"
	ObservationPartial     ObservationStatus = "partial"
)

type FileKind string

const (
	FileRegular   FileKind = "regular"
	FileDirectory FileKind = "directory"
	FileSymlink   FileKind = "symlink"
	FileSocket    FileKind = "socket"
	FileOther     FileKind = "other"
)

type Diagnostic struct {
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	Path        string   `json:"path,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type StatObservation struct {
	Path        string            `json:"path"`
	Device      uint64            `json:"device"`
	Inode       uint64            `json:"inode"`
	Mode        uint32            `json:"mode"`
	UID         int               `json:"uid"`
	GID         int               `json:"gid"`
	Kind        FileKind          `json:"kind"`
	LinkTarget  string            `json:"link_target,omitempty"`
	Status      ObservationStatus `json:"status"`
	EvidenceIDs []string          `json:"evidence_ids"`
}

func ParseStat(input []byte, evidenceID string) ([]StatObservation, []Diagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	header := false
	var observations []StatObservation
	var diagnostics []Diagnostic
	for scanner.Scan() {
		line++
		text := strings.TrimSuffix(scanner.Text(), "\r")
		if line == 1 {
			if text != "LPECO_PATH_STAT_V1" {
				return nil, []Diagnostic{{Code: "unsupported-stat-format", Message: "path stat framing header is missing", EvidenceIDs: []string{evidenceID}}}
			}
			header = true
			continue
		}
		if text == "" {
			continue
		}
		parts := strings.Split(text, "\t")
		if len(parts) >= 3 && parts[0] == "ERROR" {
			path, _ := decodeHexString(parts[1])
			diagnostics = append(diagnostics, Diagnostic{Code: "stat-unavailable", Message: strings.Join(parts[2:], " "), Path: path, EvidenceIDs: []string{evidenceID}})
			continue
		}
		if len(parts) != 9 || parts[0] != "STAT" {
			diagnostics = append(diagnostics, Diagnostic{Code: "malformed-stat-record", Message: fmt.Sprintf("line %d", line), EvidenceIDs: []string{evidenceID}})
			continue
		}
		path, pathErr := decodeHexString(parts[1])
		device, deviceErr := strconv.ParseUint(parts[2], 10, 64)
		inode, inodeErr := strconv.ParseUint(parts[3], 10, 64)
		mode, modeErr := strconv.ParseUint(parts[4], 16, 32)
		uid, uidErr := strconv.Atoi(parts[5])
		gid, gidErr := strconv.Atoi(parts[6])
		linkTarget, linkErr := decodeHexString(parts[8])
		if pathErr != nil || deviceErr != nil || inodeErr != nil || modeErr != nil || uidErr != nil || gidErr != nil || linkErr != nil || !filepath.IsAbs(path) {
			diagnostics = append(diagnostics, Diagnostic{Code: "invalid-stat-record", Message: fmt.Sprintf("line %d", line), Path: path, EvidenceIDs: []string{evidenceID}})
			continue
		}
		observations = append(observations, StatObservation{
			Path: filepath.Clean(path), Device: device, Inode: inode, Mode: uint32(mode), UID: uid, GID: gid,
			Kind: normalizeFileKind(parts[7], uint32(mode)), LinkTarget: linkTarget, Status: ObservationComplete, EvidenceIDs: []string{evidenceID},
		})
	}
	if err := scanner.Err(); err != nil {
		diagnostics = append(diagnostics, Diagnostic{Code: "stat-read-error", Message: err.Error(), EvidenceIDs: []string{evidenceID}})
	}
	if !header {
		return nil, diagnostics
	}
	return observations, diagnostics
}

func decodeHexString(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func normalizeFileKind(value string, mode uint32) FileKind {
	switch strings.ToLower(value) {
	case "regular", "regular file", "file":
		return FileRegular
	case "directory", "dir":
		return FileDirectory
	case "symlink", "symbolic link":
		return FileSymlink
	case "socket":
		return FileSocket
	}
	switch mode & 0o170000 {
	case 0o100000:
		return FileRegular
	case 0o040000:
		return FileDirectory
	case 0o120000:
		return FileSymlink
	case 0o140000:
		return FileSocket
	default:
		return FileOther
	}
}

func containsFold(value, fragment string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(fragment))
}
