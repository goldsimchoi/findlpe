package path

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

type MountObservation struct {
	ID             int      `json:"id"`
	ParentID       int      `json:"parent_id"`
	MajorMinor     string   `json:"major_minor"`
	Root           string   `json:"root"`
	MountPoint     string   `json:"mount_point"`
	Options        []string `json:"options"`
	OptionalFields []string `json:"optional_fields,omitempty"`
	FSType         string   `json:"fs_type"`
	Source         string   `json:"source"`
	SuperOptions   []string `json:"super_options"`
	ReadOnly       bool     `json:"read_only"`
	NoExec         bool     `json:"noexec"`
	NoSUID         bool     `json:"nosuid"`
	Bind           bool     `json:"bind"`
	Remote         bool     `json:"remote"`
	Pseudo         bool     `json:"pseudo"`
	EvidenceIDs    []string `json:"evidence_ids"`
}

func ParseMountInfo(input []byte, evidenceID string) ([]MountObservation, []Diagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	line := 0
	var mounts []MountObservation
	var diagnostics []Diagnostic
	for scanner.Scan() {
		line++
		fields := strings.Fields(strings.TrimSuffix(scanner.Text(), "\r"))
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if len(fields) < 10 || separator < 6 || len(fields)-separator < 4 {
			diagnostics = append(diagnostics, Diagnostic{Code: "malformed-mountinfo", Message: fmt.Sprintf("line %d", line), EvidenceIDs: []string{evidenceID}})
			continue
		}
		id, idErr := strconv.Atoi(fields[0])
		parentID, parentErr := strconv.Atoi(fields[1])
		if idErr != nil || parentErr != nil {
			diagnostics = append(diagnostics, Diagnostic{Code: "invalid-mount-id", Message: fmt.Sprintf("line %d", line), EvidenceIDs: []string{evidenceID}})
			continue
		}
		root, rootErr := unescapeMountInfo(fields[3])
		mountPoint, mountErr := unescapeMountInfo(fields[4])
		source, sourceErr := unescapeMountInfo(fields[separator+2])
		if rootErr != nil || mountErr != nil || sourceErr != nil {
			diagnostics = append(diagnostics, Diagnostic{Code: "invalid-mount-escape", Message: fmt.Sprintf("line %d", line), EvidenceIDs: []string{evidenceID}})
			continue
		}
		options := splitOptions(fields[5])
		superOptions := splitOptions(fields[separator+3])
		optional := append([]string(nil), fields[6:separator]...)
		fsType := fields[separator+1]
		mount := MountObservation{
			ID: id, ParentID: parentID, MajorMinor: fields[2], Root: filepath.Clean(root), MountPoint: filepath.Clean(mountPoint),
			Options: options, OptionalFields: optional, FSType: fsType, Source: source, SuperOptions: superOptions, EvidenceIDs: []string{evidenceID},
		}
		mount.ReadOnly = hasOption(options, "ro") || hasOption(superOptions, "ro")
		mount.NoExec = hasOption(options, "noexec") || hasOption(superOptions, "noexec")
		mount.NoSUID = hasOption(options, "nosuid") || hasOption(superOptions, "nosuid")
		mount.Bind = mount.Root != "/" || hasOption(options, "bind") || hasOption(options, "rbind") || containsValue(optional, "bind")
		mount.Remote = remoteFilesystem(fsType)
		mount.Pseudo = pseudoFilesystem(fsType)
		mounts = append(mounts, mount)
	}
	if err := scanner.Err(); err != nil {
		diagnostics = append(diagnostics, Diagnostic{Code: "mountinfo-read-error", Message: err.Error(), EvidenceIDs: []string{evidenceID}})
	}
	return mounts, diagnostics
}

func MountForPath(target string, mounts []MountObservation) (MountObservation, bool) {
	target = filepath.Clean(target)
	best := -1
	for index, mount := range mounts {
		point := filepath.Clean(mount.MountPoint)
		if target != point && point != "/" && !strings.HasPrefix(target, point+"/") {
			continue
		}
		if point == "/" || target == point || strings.HasPrefix(target, point+"/") {
			if best < 0 || len(point) > len(filepath.Clean(mounts[best].MountPoint)) {
				best = index
			}
		}
	}
	if best < 0 {
		return MountObservation{}, false
	}
	return mounts[best], true
}

func unescapeMountInfo(value string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			result.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) {
			return "", fmt.Errorf("short mountinfo escape")
		}
		octal := value[index+1 : index+4]
		parsed, err := strconv.ParseUint(octal, 8, 8)
		if err != nil {
			return "", err
		}
		result.WriteByte(byte(parsed))
		index += 3
	}
	return result.String(), nil
}

func splitOptions(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func hasOption(options []string, wanted string) bool {
	for _, option := range options {
		if option == wanted {
			return true
		}
	}
	return false
}

func containsValue(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func remoteFilesystem(value string) bool {
	switch strings.ToLower(value) {
	case "nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.sshfs", "9p", "ceph", "glusterfs":
		return true
	default:
		return false
	}
}

func pseudoFilesystem(value string) bool {
	switch strings.ToLower(value) {
	case "proc", "sysfs", "devtmpfs", "devpts", "securityfs", "cgroup", "cgroup2", "pstore", "debugfs", "tracefs", "configfs", "mqueue", "hugetlbfs", "rpc_pipefs", "autofs":
		return true
	default:
		return false
	}
}
