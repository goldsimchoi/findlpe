package context

import (
	"bufio"
	"bytes"
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
	header := false
	seen := make(map[string]bool)
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if lineNumber == 1 {
			if line != "LPECO_CONTEXT_V1" {
				return ParsedContext{}, fmt.Errorf("context header line 1: %w", errors.New("unsupported format"))
			}
			header = true
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
		}
	}
	if err := scanner.Err(); err != nil {
		return ParsedContext{}, fmt.Errorf("read context output: %w", err)
	}
	if !header || !seen["uids"] || !seen["gids"] {
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
	return parsed, nil
}

func Facts(parsed ParsedContext, evidenceID string) ([]model.Fact, error) {
	if evidenceID == "" {
		return nil, errors.New("context evidence ID is required")
	}
	confidence := model.ConfidenceHigh
	if len(parsed.MissingFacts) > 0 {
		confidence = model.ConfidenceMedium
	}
	values := []struct {
		kind  string
		value any
	}{
		{kind: "identity", value: parsed.Identity},
		{kind: "namespace", value: parsed.Namespaces},
		{kind: "security", value: parsed.Security},
		{kind: "host", value: parsed.Host},
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
			ID: id, Kind: value.kind, SourceCollector: "context", EvidenceIDs: []string{evidenceID}, Confidence: confidence, Data: data,
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
