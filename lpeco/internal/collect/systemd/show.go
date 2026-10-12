package systemd

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/normalone/lpeco/internal/systemdunit"
)

type RuntimeUnit struct {
	Name                  string                             `json:"name"`
	Names                 []string                           `json:"names"`
	Manager               string                             `json:"manager"`
	ManagerUID            int                                `json:"manager_uid"`
	LoadState             string                             `json:"load_state"`
	ActiveState           string                             `json:"active_state"`
	SubState              string                             `json:"sub_state"`
	Type                  string                             `json:"type"`
	User                  string                             `json:"user"`
	Group                 string                             `json:"group"`
	UID                   int                                `json:"uid"`
	GID                   int                                `json:"gid"`
	DynamicUser           bool                               `json:"dynamic_user"`
	MainPID               int                                `json:"main_pid"`
	ControlGroup          string                             `json:"control_group"`
	FragmentPath          string                             `json:"fragment_path"`
	DropInPaths           []string                           `json:"drop_in_paths"`
	Restart               string                             `json:"restart"`
	NoNewPrivileges       bool                               `json:"no_new_privileges"`
	CapabilityBoundingSet []string                           `json:"capability_bounding_set"`
	AmbientCapabilities   []string                           `json:"ambient_capabilities"`
	EnvironmentFiles      []string                           `json:"environment_files"`
	ExecSearchPath        []string                           `json:"exec_search_path"`
	WorkingDirectory      string                             `json:"working_directory"`
	RootDirectory         string                             `json:"root_directory"`
	RootImage             string                             `json:"root_image"`
	TriggeredBy           []string                           `json:"triggered_by"`
	Triggers              []string                           `json:"triggers"`
	ActivationUnit        string                             `json:"activation_unit"`
	NextElapse            string                             `json:"next_elapse"`
	RemainAfterExit       bool                               `json:"remain_after_exit"`
	RuntimeExec           map[string]systemdunit.ExecCommand `json:"runtime_exec"`
	Properties            map[string]string                  `json:"properties"`
	EvidenceIDs           []string                           `json:"evidence_ids"`
	MissingFacts          []string                           `json:"missing_facts"`
}

func ParseShow(input []byte, evidenceID string) ([]RuntimeUnit, []CollectorDiagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	lineNumber := 0
	header := false
	var units []RuntimeUnit
	var diagnostics []CollectorDiagnostic
	var current *RuntimeUnit
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if lineNumber == 1 {
			if line != "LPECO_SYSTEMD_SHOW_V1" {
				return nil, []CollectorDiagnostic{{Code: "unsupported-show-format", Message: "systemctl show framing header is missing", EvidenceIDs: []string{evidenceID}}}
			}
			header = true
			continue
		}
		if strings.HasPrefix(line, "UNIT\t") {
			parts := strings.Split(line, "\t")
			if len(parts) != 3 || current != nil {
				diagnostics = append(diagnostics, CollectorDiagnostic{Code: "malformed-unit-marker", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
				continue
			}
			current = &RuntimeUnit{Name: parts[2], Manager: parts[1], Properties: make(map[string]string), RuntimeExec: make(map[string]systemdunit.ExecCommand), EvidenceIDs: []string{evidenceID}}
			continue
		}
		if line == "END_UNIT" {
			if current == nil {
				diagnostics = append(diagnostics, CollectorDiagnostic{Code: "orphan-end-unit", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
				continue
			}
			finalizeRuntimeUnit(current)
			units = append(units, *current)
			current = nil
			continue
		}
		if current == nil || line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			diagnostics = append(diagnostics, CollectorDiagnostic{Code: "malformed-show-property", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
			continue
		}
		current.Properties[key] = value
	}
	if scanner.Err() != nil {
		diagnostics = append(diagnostics, CollectorDiagnostic{Code: "show-read-error", Message: scanner.Err().Error(), EvidenceIDs: []string{evidenceID}})
	}
	if current != nil {
		current.MissingFacts = append(current.MissingFacts, "truncated systemctl show unit")
		finalizeRuntimeUnit(current)
		units = append(units, *current)
		diagnostics = append(diagnostics, CollectorDiagnostic{Code: "truncated-unit", Message: current.Name, EvidenceIDs: []string{evidenceID}})
	}
	if !header {
		return nil, diagnostics
	}
	return units, diagnostics
}

func finalizeRuntimeUnit(unit *RuntimeUnit) {
	properties := unit.Properties
	if value := properties["Id"]; value != "" {
		unit.Name = value
	}
	unit.Names = strings.Fields(properties["Names"])
	unit.LoadState = properties["LoadState"]
	unit.ActiveState = properties["ActiveState"]
	unit.SubState = properties["SubState"]
	unit.Type = properties["Type"]
	unit.User = properties["User"]
	unit.Group = properties["Group"]
	unit.UID, _ = strconv.Atoi(properties["UID"])
	unit.GID, _ = strconv.Atoi(properties["GID"])
	unit.ManagerUID, _ = strconv.Atoi(properties["ManagerUID"])
	unit.DynamicUser = parseSystemdBool(properties["DynamicUser"])
	unit.MainPID, _ = strconv.Atoi(properties["MainPID"])
	unit.ControlGroup = properties["ControlGroup"]
	unit.FragmentPath = properties["FragmentPath"]
	unit.DropInPaths = strings.Fields(properties["DropInPaths"])
	unit.Restart = properties["Restart"]
	unit.NoNewPrivileges = parseSystemdBool(properties["NoNewPrivileges"])
	unit.CapabilityBoundingSet = strings.Fields(properties["CapabilityBoundingSet"])
	unit.AmbientCapabilities = strings.Fields(properties["AmbientCapabilities"])
	unit.EnvironmentFiles = parseEnvironmentFiles(properties["EnvironmentFiles"])
	if searchPath := properties["ExecSearchPath"]; searchPath != "" {
		unit.ExecSearchPath = strings.Split(searchPath, ":")
	}
	unit.WorkingDirectory = properties["WorkingDirectory"]
	unit.RootDirectory = properties["RootDirectory"]
	unit.RootImage = properties["RootImage"]
	unit.TriggeredBy = strings.Fields(properties["TriggeredBy"])
	unit.Triggers = strings.Fields(properties["Triggers"])
	unit.ActivationUnit = properties["Unit"]
	unit.NextElapse = properties["NextElapseUSecRealtime"]
	unit.RemainAfterExit = parseSystemdBool(properties["RemainAfterExit"])
	for _, directive := range []string{"ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost"} {
		if raw := properties[directive]; raw != "" {
			if parsed, ok := parseRuntimeExec(raw); ok {
				unit.RuntimeExec[directive] = parsed
			} else {
				unit.MissingFacts = append(unit.MissingFacts, directive+": unparsed runtime command")
			}
		}
	}
	for _, required := range []string{"LoadState", "ActiveState"} {
		if properties[required] == "" {
			unit.MissingFacts = append(unit.MissingFacts, required+" unavailable")
		}
	}
}

func parseRuntimeExec(raw string) (systemdunit.ExecCommand, bool) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
		trimmed = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	}
	values := make(map[string]string)
	for _, part := range strings.Split(trimmed, ";") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if found {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	commandLine := values["argv[]"]
	if commandLine == "" {
		commandLine = values["path"]
	}
	if commandLine == "" {
		return systemdunit.ExecCommand{Raw: raw, Valid: false}, false
	}
	command := systemdunit.ParseExec(commandLine)
	if path := values["path"]; path != "" {
		command.Executable = path
		command.SimpleExecutable = !strings.Contains(path, "/")
	}
	command.Raw = raw
	return command, command.Executable != ""
}

func parseEnvironmentFiles(value string) []string {
	var result []string
	for _, field := range strings.Fields(value) {
		if strings.HasPrefix(field, "(") || strings.Contains(field, "=") && !strings.HasPrefix(field, "/") && !strings.HasPrefix(field, "-") {
			continue
		}
		result = append(result, strings.TrimPrefix(field, "-"))
	}
	return result
}

func parseSystemdBool(value string) bool {
	switch strings.ToLower(value) {
	case "yes", "true", "1", "on":
		return true
	default:
		return false
	}
}
