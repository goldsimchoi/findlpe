package process

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/normalone/lpeco/internal/model"
)

type CgroupFact struct {
	Hierarchy   string `json:"hierarchy"`
	Controllers string `json:"controllers"`
	Path        string `json:"path"`
}

type ProcessFact struct {
	PID              int               `json:"pid"`
	PPID             int               `json:"ppid"`
	StartTime        uint64            `json:"start_time"`
	Name             string            `json:"name"`
	State            string            `json:"state"`
	UIDs             [4]int            `json:"uids"`
	GIDs             [4]int            `json:"gids"`
	Capabilities     map[string]uint64 `json:"capabilities"`
	NoNewPrivileges  bool              `json:"no_new_privileges"`
	Cmdline          []string          `json:"cmdline"`
	Executable       string            `json:"executable"`
	WorkingDirectory string            `json:"working_directory"`
	Root             string            `json:"root"`
	Cgroups          []CgroupFact      `json:"cgroups"`
	MissingFacts     []string          `json:"missing_facts"`
	EvidenceIDs      []string          `json:"evidence_ids"`
	Confidence       model.Confidence  `json:"confidence"`
}

type EnvironmentValue struct {
	Value     string `json:"value"`
	Sensitive bool   `json:"sensitive"`
}

type EnvironmentFact struct {
	PID          int                         `json:"pid"`
	Values       map[string]EnvironmentValue `json:"values"`
	MissingFacts []string                    `json:"missing_facts"`
	EvidenceIDs  []string                    `json:"evidence_ids"`
}

type ProcessDependencyFact struct {
	PID          int      `json:"pid"`
	OpenFiles    []string `json:"open_files"`
	MappedFiles  []string `json:"mapped_files"`
	MissingFacts []string `json:"missing_facts"`
	EvidenceIDs  []string `json:"evidence_ids"`
}

func ParseSnapshot(input []byte, evidenceID string) ([]ProcessFact, error) {
	if evidenceID == "" {
		return nil, errors.New("process evidence ID is required")
	}
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	lineNumber := 0
	header := false
	inStatus := false
	var current *ProcessFact
	var processes []ProcessFact
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if lineNumber == 1 {
			if line != "LPECO_PROC_V1" {
				return nil, errors.New("unsupported process snapshot format")
			}
			header = true
			continue
		}
		fields := strings.Split(line, "\t")
		switch fields[0] {
		case "PROCESS":
			if len(fields) != 2 || current != nil {
				return nil, fmt.Errorf("line %d: malformed PROCESS", lineNumber)
			}
			pid, err := strconv.Atoi(fields[1])
			if err != nil || pid <= 0 {
				return nil, fmt.Errorf("line %d: malformed PID", lineNumber)
			}
			current = &ProcessFact{PID: pid, Capabilities: make(map[string]uint64), EvidenceIDs: []string{evidenceID}}
		case "STATUS":
			if current == nil {
				return nil, fmt.Errorf("line %d: STATUS outside process", lineNumber)
			}
			inStatus = true
		case "END_STATUS":
			inStatus = false
		case "END_PROCESS":
			if current == nil {
				return nil, fmt.Errorf("line %d: END_PROCESS without process", lineNumber)
			}
			finalizeProcess(current)
			processes = append(processes, *current)
			current = nil
			inStatus = false
		default:
			if current == nil {
				continue
			}
			if inStatus {
				if err := parseStatusLine(current, line); err != nil {
					return nil, fmt.Errorf("line %d: %w", lineNumber, err)
				}
				continue
			}
			if err := parseProcessField(current, fields); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNumber, err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read process snapshot: %w", err)
	}
	if !header || current != nil {
		return nil, errors.New("truncated process snapshot")
	}
	if processes == nil {
		processes = []ProcessFact{}
	}
	return processes, nil
}

func parseStatusLine(process *ProcessFact, line string) error {
	key, value, found := strings.Cut(line, ":")
	if !found {
		return nil
	}
	value = strings.TrimSpace(value)
	switch key {
	case "Name":
		process.Name = value
	case "State":
		process.State = value
	case "PPid":
		process.PPID, _ = strconv.Atoi(value)
	case "Uid":
		ids, err := parseFourIDs(value)
		if err != nil {
			return fmt.Errorf("Uid: %w", err)
		}
		process.UIDs = ids
	case "Gid":
		ids, err := parseFourIDs(value)
		if err != nil {
			return fmt.Errorf("Gid: %w", err)
		}
		process.GIDs = ids
	case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
		capability, err := strconv.ParseUint(value, 16, 64)
		if err != nil {
			return err
		}
		name := map[string]string{"CapInh": "inheritable", "CapPrm": "permitted", "CapEff": "effective", "CapBnd": "bounding", "CapAmb": "ambient"}[key]
		process.Capabilities[name] = capability
	case "NoNewPrivs":
		process.NoNewPrivileges = value == "1"
	}
	return nil
}

func parseProcessField(process *ProcessFact, fields []string) error {
	if len(fields) < 2 {
		return nil
	}
	switch fields[0] {
	case "STARTTIME":
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return err
		}
		process.StartTime = value
	case "CMDLINE_HEX":
		decoded, err := decodeHex(fields[1])
		if err != nil {
			return err
		}
		for _, argument := range bytes.Split(decoded, []byte{0}) {
			if len(argument) > 0 {
				process.Cmdline = append(process.Cmdline, string(argument))
			}
		}
	case "EXE_HEX", "CWD_HEX", "ROOT_HEX":
		decoded, err := decodeHex(fields[1])
		if err != nil {
			return err
		}
		switch fields[0] {
		case "EXE_HEX":
			process.Executable = string(decoded)
		case "CWD_HEX":
			process.WorkingDirectory = string(decoded)
		case "ROOT_HEX":
			process.Root = string(decoded)
		}
	case "CGROUP":
		parts := strings.SplitN(fields[1], ":", 3)
		if len(parts) != 3 {
			return errors.New("malformed cgroup entry")
		}
		process.Cgroups = append(process.Cgroups, CgroupFact{Hierarchy: parts[0], Controllers: parts[1], Path: parts[2]})
	case "ERROR":
		if len(fields) >= 3 {
			process.MissingFacts = append(process.MissingFacts, fields[1]+": "+strings.Join(fields[2:], "\t"))
		}
	}
	return nil
}

func finalizeProcess(process *ProcessFact) {
	statusMissing := false
	for _, missing := range process.MissingFacts {
		if strings.HasPrefix(missing, "status:") {
			statusMissing = true
			break
		}
	}
	switch {
	case statusMissing || process.StartTime == 0:
		process.Confidence = model.ConfidenceLow
	case len(process.MissingFacts) > 0:
		process.Confidence = model.ConfidenceMedium
	default:
		process.Confidence = model.ConfidenceHigh
	}
}

func ParseEnvironment(input []byte, pid int, evidenceID string) (EnvironmentFact, error) {
	result := EnvironmentFact{PID: pid, Values: make(map[string]EnvironmentValue), EvidenceIDs: []string{evidenceID}}
	scanner := bufio.NewScanner(bytes.NewReader(input))
	header := false
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		fields := strings.Split(strings.TrimSuffix(scanner.Text(), "\r"), "\t")
		if lineNumber == 1 {
			if len(fields) != 1 || fields[0] != "LPECO_ENV_V1" {
				return EnvironmentFact{}, errors.New("unsupported environment format")
			}
			header = true
			continue
		}
		if len(fields) >= 3 && fields[0] == "ENV" {
			key, err := decodeHex(fields[1])
			if err != nil {
				return EnvironmentFact{}, fmt.Errorf("line %d key: %w", lineNumber, err)
			}
			value, err := decodeHex(fields[2])
			if err != nil {
				return EnvironmentFact{}, fmt.Errorf("line %d value: %w", lineNumber, err)
			}
			if allowedEnvironmentKey(string(key)) {
				result.Values[string(key)] = EnvironmentValue{Value: string(value), Sensitive: true}
			}
		} else if len(fields) >= 3 && fields[0] == "ERROR" {
			result.MissingFacts = append(result.MissingFacts, strings.Join(fields[1:], ": "))
		}
	}
	if err := scanner.Err(); err != nil {
		return EnvironmentFact{}, err
	}
	if !header || evidenceID == "" {
		return EnvironmentFact{}, errors.New("environment header and evidence ID are required")
	}
	return result, nil
}

func ParseDependencies(input []byte, pid int, evidenceID string) (ProcessDependencyFact, error) {
	result := ProcessDependencyFact{PID: pid, EvidenceIDs: []string{evidenceID}}
	scanner := bufio.NewScanner(bytes.NewReader(input))
	header := false
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		fields := strings.Split(strings.TrimSuffix(scanner.Text(), "\r"), "\t")
		if lineNumber == 1 {
			if len(fields) != 1 || fields[0] != "LPECO_DEP_V1" {
				return ProcessDependencyFact{}, errors.New("unsupported process dependency format")
			}
			header = true
			continue
		}
		switch {
		case len(fields) == 3 && fields[0] == "FD":
			path, err := decodeHex(fields[2])
			if err != nil {
				return ProcessDependencyFact{}, fmt.Errorf("line %d FD path: %w", lineNumber, err)
			}
			result.OpenFiles = append(result.OpenFiles, string(path))
		case len(fields) == 2 && fields[0] == "MAP":
			path, err := decodeHex(fields[1])
			if err != nil {
				return ProcessDependencyFact{}, fmt.Errorf("line %d MAP path: %w", lineNumber, err)
			}
			result.MappedFiles = append(result.MappedFiles, string(path))
		case len(fields) >= 3 && fields[0] == "ERROR":
			result.MissingFacts = append(result.MissingFacts, strings.Join(fields[1:], ": "))
		}
	}
	if err := scanner.Err(); err != nil {
		return ProcessDependencyFact{}, err
	}
	if !header || evidenceID == "" {
		return ProcessDependencyFact{}, errors.New("dependency header and evidence ID are required")
	}
	return result, nil
}

func EnvironmentFacts(environment EnvironmentFact) ([]model.Fact, error) {
	data, err := json.Marshal(environment)
	if err != nil {
		return nil, err
	}
	id, err := model.StableID("fact", struct {
		PID  int
		Kind string
	}{environment.PID, "environment"})
	if err != nil {
		return nil, err
	}
	confidence := model.ConfidenceHigh
	if len(environment.MissingFacts) > 0 {
		confidence = model.ConfidenceMedium
	}
	return []model.Fact{{ID: id, Kind: "process_environment", SourceCollector: "process", EvidenceIDs: environment.EvidenceIDs, Confidence: confidence, Data: data}}, nil
}

func DependencyFacts(dependencies ProcessDependencyFact) ([]model.Fact, error) {
	data, err := json.Marshal(dependencies)
	if err != nil {
		return nil, err
	}
	id, err := model.StableID("fact", struct {
		PID  int
		Kind string
	}{dependencies.PID, "dependencies"})
	if err != nil {
		return nil, err
	}
	confidence := model.ConfidenceHigh
	if len(dependencies.MissingFacts) > 0 {
		confidence = model.ConfidenceMedium
	}
	return []model.Fact{{ID: id, Kind: "process_dependency", SourceCollector: "process", EvidenceIDs: dependencies.EvidenceIDs, Confidence: confidence, Data: data}}, nil
}

func Facts(processes []ProcessFact) ([]model.Fact, error) {
	var facts []model.Fact
	for _, process := range processes {
		data, err := json.Marshal(process)
		if err != nil {
			return nil, err
		}
		id, err := model.StableID("fact", struct {
			PID   int
			Start uint64
		}{process.PID, process.StartTime})
		if err != nil {
			return nil, err
		}
		facts = append(facts, model.Fact{ID: id, Kind: "process", SourceCollector: "process", EvidenceIDs: process.EvidenceIDs, Confidence: process.Confidence, Data: data})
		for _, cgroup := range process.Cgroups {
			cgroupData, err := json.Marshal(struct {
				PID int `json:"pid"`
				CgroupFact
			}{PID: process.PID, CgroupFact: cgroup})
			if err != nil {
				return nil, err
			}
			cgroupID, err := model.StableID("fact", struct {
				PID  int
				Path string
			}{process.PID, cgroup.Path})
			if err != nil {
				return nil, err
			}
			facts = append(facts, model.Fact{ID: cgroupID, Kind: "cgroup", SourceCollector: "process", EvidenceIDs: process.EvidenceIDs, Confidence: process.Confidence, Data: cgroupData})
		}
	}
	return facts, nil
}

func decodeHex(value string) ([]byte, error) {
	if len(value)%2 != 0 {
		return nil, errors.New("odd-length hexadecimal value")
	}
	return hex.DecodeString(value)
}

func parseFourIDs(value string) ([4]int, error) {
	fields := strings.Fields(value)
	if len(fields) != 4 {
		return [4]int{}, fmt.Errorf("got %d IDs, want 4", len(fields))
	}
	var result [4]int
	for index, field := range fields {
		parsed, err := strconv.Atoi(field)
		if err != nil {
			return [4]int{}, err
		}
		result[index] = parsed
	}
	return result, nil
}

func allowedEnvironmentKey(key string) bool {
	switch key {
	case "PATH", "LD_LIBRARY_PATH", "LD_PRELOAD", "PYTHONPATH", "PERL5LIB", "RUBYLIB", "GEM_PATH", "NODE_PATH", "CLASSPATH":
		return true
	default:
		return false
	}
}
