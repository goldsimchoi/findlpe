package path

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/normalone/lpeco/internal/model"
)

type ACLTag string

const (
	ACLUser       ACLTag = "user"
	ACLNamedUser  ACLTag = "named_user"
	ACLGroup      ACLTag = "group"
	ACLNamedGroup ACLTag = "named_group"
	ACLMask       ACLTag = "mask"
	ACLOther      ACLTag = "other"
)

type PermissionSet struct {
	Read    bool `json:"read"`
	Write   bool `json:"write"`
	Execute bool `json:"execute"`
}

type ACLEntry struct {
	Tag         ACLTag        `json:"tag"`
	Qualifier   int           `json:"qualifier,omitempty"`
	Permissions PermissionSet `json:"permissions"`
	Default     bool          `json:"default"`
}

type ACLObservation struct {
	Path         string            `json:"path"`
	Status       ObservationStatus `json:"status"`
	Entries      []ACLEntry        `json:"entries"`
	EvidenceIDs  []string          `json:"evidence_ids"`
	MissingFacts []string          `json:"missing_facts,omitempty"`
}

func ParseACL(input []byte, evidenceID string) ([]ACLObservation, []Diagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	var current *ACLObservation
	var observations []ACLObservation
	var diagnostics []Diagnostic
	flush := func(partial bool) {
		if current == nil {
			return
		}
		if partial {
			current.Status = ObservationPartial
			current.MissingFacts = append(current.MissingFacts, "truncated ACL record")
		}
		observations = append(observations, *current)
		current = nil
	}
	for scanner.Scan() {
		line++
		text := strings.TrimSuffix(scanner.Text(), "\r")
		if line == 1 {
			if text != "LPECO_PATH_ACL_V1" {
				return nil, []Diagnostic{{Code: "unsupported-acl-format", Message: "ACL framing header is missing", EvidenceIDs: []string{evidenceID}}}
			}
			continue
		}
		parts := strings.Split(text, "\t")
		if len(parts) == 2 && parts[0] == "ACL" {
			flush(true)
			path, err := decodeHexString(parts[1])
			if err != nil {
				diagnostics = append(diagnostics, Diagnostic{Code: "invalid-acl-path", Message: fmt.Sprintf("line %d", line), EvidenceIDs: []string{evidenceID}})
				continue
			}
			current = &ACLObservation{Path: path, Status: ObservationComplete, EvidenceIDs: []string{evidenceID}}
			continue
		}
		if len(parts) >= 3 && parts[0] == "ERROR" {
			flush(true)
			path, _ := decodeHexString(parts[1])
			observations = append(observations, ACLObservation{Path: path, Status: ObservationUnavailable, EvidenceIDs: []string{evidenceID}, MissingFacts: []string{strings.Join(parts[2:], " ")}})
			continue
		}
		if text == "END_ACL" {
			flush(false)
			continue
		}
		if current == nil || text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		entry, err := parseACLEntry(text)
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic{Code: "invalid-acl-entry", Message: fmt.Sprintf("line %d: %v", line, err), Path: current.Path, EvidenceIDs: []string{evidenceID}})
			current.Status = ObservationPartial
			current.MissingFacts = append(current.MissingFacts, "unparsed ACL entry")
			continue
		}
		current.Entries = append(current.Entries, entry)
	}
	flush(true)
	if err := scanner.Err(); err != nil {
		diagnostics = append(diagnostics, Diagnostic{Code: "acl-read-error", Message: err.Error(), EvidenceIDs: []string{evidenceID}})
	}
	return observations, diagnostics
}

func parseACLEntry(value string) (ACLEntry, error) {
	entry := ACLEntry{Qualifier: -1}
	if strings.HasPrefix(value, "default:") {
		entry.Default = true
		value = strings.TrimPrefix(value, "default:")
	}
	parts := strings.Split(value, ":")
	if len(parts) != 3 {
		return entry, fmt.Errorf("expected tag:qualifier:permissions")
	}
	switch parts[0] {
	case "user":
		entry.Tag = ACLUser
		if parts[1] != "" {
			entry.Tag = ACLNamedUser
		}
	case "group":
		entry.Tag = ACLGroup
		if parts[1] != "" {
			entry.Tag = ACLNamedGroup
		}
	case "mask":
		entry.Tag = ACLMask
	case "other":
		entry.Tag = ACLOther
	default:
		return entry, fmt.Errorf("unknown ACL tag %q", parts[0])
	}
	if parts[1] != "" {
		qualifier, err := strconv.Atoi(parts[1])
		if err != nil {
			return entry, fmt.Errorf("non-numeric ACL qualifier %q", parts[1])
		}
		entry.Qualifier = qualifier
	}
	permissions, err := parsePermissions(parts[2])
	if err != nil {
		return entry, err
	}
	entry.Permissions = permissions
	return entry, nil
}

func parsePermissions(value string) (PermissionSet, error) {
	if len(value) < 3 {
		return PermissionSet{}, fmt.Errorf("invalid ACL permissions %q", value)
	}
	value = value[:3]
	if (value[0] != 'r' && value[0] != '-') || (value[1] != 'w' && value[1] != '-') || (value[2] != 'x' && value[2] != '-') {
		return PermissionSet{}, fmt.Errorf("invalid ACL permissions %q", value)
	}
	return PermissionSet{Read: value[0] == 'r', Write: value[1] == 'w', Execute: value[2] == 'x'}, nil
}

func EffectivePermissions(principal model.Principal, stat StatObservation, acl ACLObservation) (PermissionSet, bool) {
	if acl.Status != ObservationComplete {
		return PermissionSet{}, false
	}
	if principal.UID == 0 || hasCapability(principal, "CAP_DAC_OVERRIDE") {
		permissions := PermissionSet{Read: true, Write: true, Execute: stat.Kind == FileDirectory || stat.Mode&0o111 != 0}
		return permissions, true
	}
	entries := accessEntries(acl.Entries)
	if len(entries) == 0 {
		return modePermissions(principal, stat), true
	}
	mask := PermissionSet{Read: true, Write: true, Execute: true}
	hasNamedEntry := false
	hasMask := false
	for _, entry := range entries {
		if entry.Tag == ACLMask {
			mask = entry.Permissions
			hasMask = true
		}
		if entry.Tag == ACLNamedUser || entry.Tag == ACLNamedGroup {
			hasNamedEntry = true
		}
	}
	if hasNamedEntry && !hasMask {
		return PermissionSet{}, false
	}
	if principal.UID == stat.UID {
		if entry, ok := firstEntry(entries, ACLUser, -1); ok {
			return entry.Permissions, true
		}
		return permissionsFromBits((stat.Mode >> 6) & 7), true
	}
	for _, entry := range entries {
		if entry.Tag == ACLNamedUser && entry.Qualifier == principal.UID {
			return intersectPermissions(entry.Permissions, mask), true
		}
	}
	groupPermissions := PermissionSet{}
	matchedGroup := false
	if principalHasGID(principal, stat.GID) {
		matchedGroup = true
		if entry, ok := firstEntry(entries, ACLGroup, -1); ok {
			groupPermissions = unionPermissions(groupPermissions, entry.Permissions)
		} else {
			groupPermissions = permissionsFromBits((stat.Mode >> 3) & 7)
		}
	}
	for _, entry := range entries {
		if entry.Tag == ACLNamedGroup && principalHasGID(principal, entry.Qualifier) {
			matchedGroup = true
			groupPermissions = unionPermissions(groupPermissions, entry.Permissions)
		}
	}
	if matchedGroup {
		return intersectPermissions(groupPermissions, mask), true
	}
	if entry, ok := firstEntry(entries, ACLOther, -1); ok {
		return entry.Permissions, true
	}
	return permissionsFromBits(stat.Mode & 7), true
}

func modePermissions(principal model.Principal, stat StatObservation) PermissionSet {
	bits := stat.Mode & 7
	if principal.UID == stat.UID {
		bits = (stat.Mode >> 6) & 7
	} else if principalHasGID(principal, stat.GID) {
		bits = (stat.Mode >> 3) & 7
	}
	return permissionsFromBits(bits)
}

func permissionsFromBits(bits uint32) PermissionSet {
	return PermissionSet{Read: bits&4 != 0, Write: bits&2 != 0, Execute: bits&1 != 0}
}

func accessEntries(entries []ACLEntry) []ACLEntry {
	result := make([]ACLEntry, 0, len(entries))
	for _, entry := range entries {
		if !entry.Default {
			result = append(result, entry)
		}
	}
	return result
}

func firstEntry(entries []ACLEntry, tag ACLTag, qualifier int) (ACLEntry, bool) {
	for _, entry := range entries {
		if entry.Tag == tag && (qualifier < 0 || entry.Qualifier == qualifier) {
			return entry, true
		}
	}
	return ACLEntry{}, false
}

func intersectPermissions(left, right PermissionSet) PermissionSet {
	return PermissionSet{Read: left.Read && right.Read, Write: left.Write && right.Write, Execute: left.Execute && right.Execute}
}

func unionPermissions(left, right PermissionSet) PermissionSet {
	return PermissionSet{Read: left.Read || right.Read, Write: left.Write || right.Write, Execute: left.Execute || right.Execute}
}

func principalHasGID(principal model.Principal, gid int) bool {
	if principal.GID == gid {
		return true
	}
	for _, candidate := range principal.SupplementaryGIDs {
		if candidate == gid {
			return true
		}
	}
	return false
}

func hasCapability(principal model.Principal, capability string) bool {
	for _, candidate := range principal.Capabilities {
		if strings.EqualFold(candidate, capability) {
			return true
		}
	}
	return false
}
