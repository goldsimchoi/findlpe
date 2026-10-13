package context

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/normalone/lpeco/internal/model"
)

type IdentityFact struct {
	UIDs            [4]int            `json:"uids"`
	GIDs            [4]int            `json:"gids"`
	Groups          []int             `json:"groups"`
	Capabilities    map[string]uint64 `json:"capabilities"`
	NoNewPrivileges bool              `json:"no_new_privileges"`
	SeccompMode     int               `json:"seccomp_mode"`
	MissingFacts    []string          `json:"missing_facts,omitempty"`
}

type NamespaceFact struct {
	IDs          map[string]string `json:"ids"`
	MissingFacts []string          `json:"missing_facts,omitempty"`
}

type SecurityFact struct {
	LSM          map[string]string `json:"lsm"`
	MissingFacts []string          `json:"missing_facts,omitempty"`
}

type HostFact struct {
	OS                string          `json:"os"`
	Architecture      string          `json:"architecture"`
	InitSystem        string          `json:"init_system"`
	SystemdRunning    bool            `json:"systemd_running"`
	AvailableCommands map[string]bool `json:"available_commands"`
	MissingFacts      []string        `json:"missing_facts,omitempty"`
}

type ParsedContext struct {
	Identity     IdentityFact
	Namespaces   NamespaceFact
	Security     SecurityFact
	Host         HostFact
	Distribution model.DistributionProfile
	Kernel       model.KernelProfile
	MissingFacts []string
}

func ParseOutput(input []byte) (ParsedContext, error) {
	parsed := ParsedContext{
		Identity:   IdentityFact{Capabilities: make(map[string]uint64)},
		Namespaces: NamespaceFact{IDs: make(map[string]string)},
		Security:   SecurityFact{LSM: make(map[string]string)},
		Host:       HostFact{AvailableCommands: make(map[string]bool)},
	}
	scanner := bufio.NewScanner(bytes.NewReader(input))
	lineNumber := 0
	inStatus := false
	frameVersion := 0
	seen := make(map[string]bool)
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if lineNumber == 1 {
			switch line {
			case "LPECO_CONTEXT_V1":
				frameVersion = 1
			case "LPECO_CONTEXT_V2":
				frameVersion = 2
			default:
				return ParsedContext{}, fmt.Errorf("context header line 1: %w", errors.New("unsupported format"))
			}
			continue
		}
		switch line {
		case "STATUS":
			inStatus = true
			continue
		case "END_STATUS":
			inStatus = false
			continue
		}
		if inStatus {
			key, value, found := strings.Cut(line, ":")
			if !found {
				continue
			}
			value = strings.TrimSpace(value)
			switch key {
			case "Uid":
				ids, err := parseFourIDs(value)
				if err != nil {
					return ParsedContext{}, fmt.Errorf("line %d Uid: %w", lineNumber, err)
				}
				parsed.Identity.UIDs = ids
				seen["uids"] = true
			case "Gid":
				ids, err := parseFourIDs(value)
				if err != nil {
					return ParsedContext{}, fmt.Errorf("line %d Gid: %w", lineNumber, err)
				}
				parsed.Identity.GIDs = ids
				seen["gids"] = true
			case "Groups":
				groups, err := parseInts(value)
				if err != nil {
					return ParsedContext{}, fmt.Errorf("line %d Groups: %w", lineNumber, err)
				}
				parsed.Identity.Groups = groups
				seen["groups"] = true
			case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
				capability, err := strconv.ParseUint(value, 16, 64)
				if err != nil {
					return ParsedContext{}, fmt.Errorf("line %d %s: %w", lineNumber, key, err)
				}
				name := map[string]string{"CapInh": "inheritable", "CapPrm": "permitted", "CapEff": "effective", "CapBnd": "bounding", "CapAmb": "ambient"}[key]
				parsed.Identity.Capabilities[name] = capability
				seen["capabilities"] = true
			case "NoNewPrivs":
				parsed.Identity.NoNewPrivileges = value == "1"
				seen["no_new_privileges"] = true
			case "Seccomp":
				mode, err := strconv.Atoi(value)
				if err != nil {
					return ParsedContext{}, fmt.Errorf("line %d Seccomp: %w", lineNumber, err)
				}
				parsed.Identity.SeccompMode = mode
				seen["seccomp"] = true
			}
			continue
		}
		fields := strings.Split(line, "\t")
		switch fields[0] {
		case "NS":
			if len(fields) == 3 {
				parsed.Namespaces.IDs[fields[1]] = fields[2]
				seen["namespaces"] = true
			}
		case "LSM":
			if len(fields) == 3 {
				parsed.Security.LSM[fields[1]] = fields[2]
				seen["lsm"] = true
			}
		case "OS":
			if len(fields) == 2 {
				parsed.Host.OS = fields[1]
			}
		case "ARCH":
			if len(fields) == 2 {
				parsed.Host.Architecture = fields[1]
			}
		case "INIT":
			if len(fields) == 2 {
				parsed.Host.InitSystem = fields[1]
			}
		case "SYSTEMD_RUNNING":
			if len(fields) == 2 {
				parsed.Host.SystemdRunning = fields[1] == "1"
			}
		case "COMMAND":
			if len(fields) == 3 {
				parsed.Host.AvailableCommands[fields[1]] = fields[2] == "1"
			}
		case "OS_RELEASE":
			if frameVersion != 2 || len(fields) != 4 {
				continue
			}
			if seen["os-release"] {
				parsed.Distribution = model.DistributionProfile{MissingFacts: []string{"os-release record is duplicated"}, Confidence: model.ConfidenceMedium}
				continue
			}
			seen["os-release"] = true
			path, pathErr := decodeContextHex(fields[2])
			if pathErr != nil {
				parsed.Distribution = model.DistributionProfile{MissingFacts: []string{"os-release path frame is malformed"}, Confidence: model.ConfidenceMedium}
				continue
			}
			parsed.Distribution.SourcePath = path
			switch fields[1] {
			case "readable":
				content, decodeErr := hex.DecodeString(fields[3])
				if decodeErr != nil {
					parsed.Distribution.MissingFacts = []string{"os-release content frame is malformed"}
					parsed.Distribution.Confidence = model.ConfidenceMedium
					continue
				}
				profile, missing := ParseOSRelease(content)
				profile.SourcePath = path
				profile.MissingFacts = uniqueSortedStrings(missing)
				profile.Confidence = confidenceForMissing(profile.MissingFacts)
				parsed.Distribution = profile
			case "unreadable":
				parsed.Distribution.MissingFacts = []string{"os-release is unreadable"}
				parsed.Distribution.Confidence = model.ConfidenceMedium
			case "absent":
				parsed.Distribution.MissingFacts = []string{"os-release is absent"}
				parsed.Distribution.Confidence = model.ConfidenceMedium
			default:
				parsed.Distribution.MissingFacts = []string{"os-release status is malformed"}
				parsed.Distribution.Confidence = model.ConfidenceMedium
			}
		case "KERNEL":
			if frameVersion != 2 || len(fields) != 3 {
				continue
			}
			if seen["kernel"] {
				parsed.Kernel = model.KernelProfile{MissingFacts: []string{"kernel record is duplicated"}, Confidence: model.ConfidenceMedium}
				continue
			}
			seen["kernel"] = true
			release, releaseErr := decodeContextHex(fields[1])
			version, versionErr := decodeContextHex(fields[2])
			if releaseErr != nil || versionErr != nil {
				parsed.Kernel.MissingFacts = []string{"kernel frame is malformed"}
				parsed.Kernel.Confidence = model.ConfidenceMedium
				continue
			}
			parsed.Kernel.Release = release
			parsed.Kernel.Version = version
		}
	}
	if err := scanner.Err(); err != nil {
		return ParsedContext{}, fmt.Errorf("read context output: %w", err)
	}
	if frameVersion == 0 || !seen["uids"] || !seen["gids"] {
		return ParsedContext{}, errors.New("context output lacks required UID/GID data")
	}
	for _, name := range []string{"groups", "capabilities", "no_new_privileges", "seccomp", "namespaces", "lsm"} {
		if !seen[name] {
			parsed.MissingFacts = append(parsed.MissingFacts, name)
		}
	}
	sort.Strings(parsed.MissingFacts)
	parsed.Identity.MissingFacts = append([]string(nil), parsed.MissingFacts...)
	parsed.Namespaces.MissingFacts = append([]string(nil), parsed.MissingFacts...)
	parsed.Security.MissingFacts = append([]string(nil), parsed.MissingFacts...)
	parsed.Host.MissingFacts = append([]string(nil), parsed.MissingFacts...)
	if frameVersion == 1 {
		parsed.Distribution = model.DistributionProfile{
			MissingFacts: []string{"distribution unavailable in legacy context frame"}, Confidence: model.ConfidenceMedium,
		}
		parsed.Kernel = model.KernelProfile{
			Architecture: parsed.Host.Architecture,
			MissingFacts: []string{"kernel unavailable in legacy context frame"}, Confidence: model.ConfidenceMedium,
		}
	} else {
		if !seen["os-release"] {
			parsed.Distribution = model.DistributionProfile{
				MissingFacts: []string{"os-release record is missing"}, Confidence: model.ConfidenceMedium,
			}
		}
		if !seen["kernel"] {
			parsed.Kernel = model.KernelProfile{
				MissingFacts: []string{"kernel record is missing"}, Confidence: model.ConfidenceMedium,
			}
		}
		parsed.Kernel.Architecture = parsed.Host.Architecture
		if parsed.Kernel.Release == "" {
			parsed.Kernel.MissingFacts = append(parsed.Kernel.MissingFacts, "running kernel release is missing")
		}
		if parsed.Kernel.Version == "" {
			parsed.Kernel.MissingFacts = append(parsed.Kernel.MissingFacts, "running kernel build string is missing")
		}
		parsed.Kernel.MissingFacts = uniqueSortedStrings(parsed.Kernel.MissingFacts)
		parsed.Kernel.Confidence = confidenceForMissing(parsed.Kernel.MissingFacts)
	}
	return parsed, nil
}

func ParseOSRelease(input []byte) (model.DistributionProfile, []string) {
	profile := model.DistributionProfile{}
	if bytes.IndexByte(input, 0) >= 0 {
		return profile, []string{"os-release contains NUL"}
	}

	values := make(map[string]string)
	counts := make(map[string]int)
	var missing []string
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 4*1024), 512*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, raw, found := strings.Cut(line, "=")
		if !found || !validOSReleaseKey(key) {
			continue
		}
		if key != "ID" && key != "VERSION_ID" && key != "VERSION_CODENAME" && key != "ID_LIKE" {
			continue
		}
		counts[key]++
		value, err := parseOSReleaseValue(raw)
		if err != nil {
			missing = append(missing, "os-release "+key+" is malformed")
			delete(values, key)
			continue
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		missing = append(missing, "os-release cannot be read completely")
	}
	for _, key := range []string{"ID", "VERSION_ID"} {
		if counts[key] > 1 {
			delete(values, key)
			missing = append(missing, "os-release "+key+" is duplicated")
		}
	}
	profile.ID = values["ID"]
	profile.VersionID = values["VERSION_ID"]
	profile.VersionCodename = values["VERSION_CODENAME"]
	profile.IDLike = uniqueSortedStrings(strings.Fields(values["ID_LIKE"]))
	if profile.ID == "" && counts["ID"] == 0 {
		missing = append(missing, "os-release ID is missing")
	}
	if profile.VersionID == "" && counts["VERSION_ID"] == 0 {
		missing = append(missing, "os-release VERSION_ID is missing")
	}
	if profile.ID == "ubuntu" && profile.VersionID != "" {
		profile.Channel = "standard"
	}
	return profile, uniqueSortedStrings(missing)
}

func validOSReleaseKey(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character != '_' && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func parseOSReleaseValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if value[0] == '\'' {
		if len(value) < 2 || value[len(value)-1] != '\'' || strings.Contains(value[1:len(value)-1], "'") {
			return "", errors.New("malformed single-quoted value")
		}
		return value[1 : len(value)-1], nil
	}
	doubleQuoted := value[0] == '"'
	if doubleQuoted {
		if len(value) < 2 || value[len(value)-1] != '"' {
			return "", errors.New("malformed double-quoted value")
		}
		value = value[1 : len(value)-1]
	} else if strings.ContainsAny(value, " \t\r\n\"'") {
		return "", errors.New("malformed unquoted value")
	}

	var result strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			result.WriteByte(value[index])
			continue
		}
		if index+1 >= len(value) {
			return "", errors.New("trailing escape")
		}
		next := value[index+1]
		if doubleQuoted && next != '$' && next != '"' && next != '\\' && next != '`' {
			result.WriteByte('\\')
			continue
		}
		result.WriteByte(next)
		index++
	}
	return result.String(), nil
}

func decodeContextHex(value string) (string, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func confidenceForMissing(missing []string) model.Confidence {
	if len(missing) == 0 {
		return model.ConfidenceHigh
	}
	return model.ConfidenceMedium
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil
	}
	sort.Strings(result)
	return result
}

func Facts(parsed ParsedContext, evidenceID string) ([]model.Fact, error) {
	if evidenceID == "" {
		return nil, errors.New("context evidence ID is required")
	}
	confidence := confidenceForMissing(parsed.MissingFacts)
	distribution := parsed.Distribution
	distribution.EvidenceIDs = []string{evidenceID}
	kernel := parsed.Kernel
	kernel.EvidenceIDs = []string{evidenceID}
	values := []struct {
		kind       string
		value      any
		confidence model.Confidence
		missing    []string
	}{
		{kind: "identity", value: parsed.Identity, confidence: confidence, missing: parsed.MissingFacts},
		{kind: "namespace", value: parsed.Namespaces, confidence: confidence, missing: parsed.MissingFacts},
		{kind: "security", value: parsed.Security, confidence: confidence, missing: parsed.MissingFacts},
		{kind: "host", value: parsed.Host, confidence: confidence, missing: parsed.MissingFacts},
		{kind: "distribution", value: distribution, confidence: distribution.Confidence, missing: distribution.MissingFacts},
		{kind: "kernel", value: kernel, confidence: kernel.Confidence, missing: kernel.MissingFacts},
	}
	facts := make([]model.Fact, 0, len(values))
	for _, value := range values {
		data, err := json.Marshal(value.value)
		if err != nil {
			return nil, err
		}
		id, err := model.StableID("fact", struct {
			Kind string
			Data json.RawMessage
		}{value.kind, data})
		if err != nil {
			return nil, err
		}
		facts = append(facts, model.Fact{
			ID: id, Kind: value.kind, SourceCollector: "context", EvidenceIDs: []string{evidenceID}, Confidence: value.confidence,
			MissingFacts: append([]string(nil), value.missing...), Data: data,
		})
	}
	return facts, nil
}

func parseFourIDs(value string) ([4]int, error) {
	values, err := parseInts(value)
	if err != nil {
		return [4]int{}, err
	}
	if len(values) != 4 {
		return [4]int{}, fmt.Errorf("got %d values, want 4", len(values))
	}
	return [4]int{values[0], values[1], values[2], values[3]}, nil
}

func parseInts(value string) ([]int, error) {
	fields := strings.Fields(value)
	result := make([]int, 0, len(fields))
	for _, field := range fields {
		parsed, err := strconv.Atoi(field)
		if err != nil {
			return nil, err
		}
		result = append(result, parsed)
	}
	return result, nil
}
