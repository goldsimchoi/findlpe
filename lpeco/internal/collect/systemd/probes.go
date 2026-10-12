package systemd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

const showScript = `printf 'LPECO_SYSTEMD_SHOW_V1\n'
case "$1" in
  system) _lpeco_scope= ;;
  user) _lpeco_scope=--user ;;
  *) printf 'ERROR\tmanager\tinvalid manager\n' >&2; exit 64 ;;
esac
LC_ALL=C systemctl $_lpeco_scope list-units --all --plain --no-legend --no-pager --type=service --type=timer --type=socket --type=path 2>/dev/null |
awk 'NF { print $1 }' |
while IFS= read -r _lpeco_unit; do
  [ -n "$_lpeco_unit" ] || continue
  printf 'UNIT\t%s\t%s\n' "$1" "$_lpeco_unit"
  LC_ALL=C systemctl $_lpeco_scope show --no-pager \
    --property=Id,Names,LoadState,ActiveState,SubState,Type,User,Group,UID,GID,DynamicUser,MainPID,ControlGroup,FragmentPath,DropInPaths,Restart,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,EnvironmentFiles,ExecSearchPath,WorkingDirectory,RootDirectory,RootImage,ExecCondition,ExecStartPre,ExecStart,ExecStartPost,ExecReload,ExecStop,ExecStopPost,TriggeredBy,Triggers,Unit,NextElapseUSecRealtime,RemainAfterExit \
    -- "$_lpeco_unit" 2>/dev/null || printf 'CollectionError=systemctl show failed\n'
  if [ "$1" = user ]; then printf 'ManagerUID=%s\n' "$(id -u 2>/dev/null)"; fi
  printf 'END_UNIT\n'
done`

const unitFileInventoryScript = `printf 'LPECO_SYSTEMD_SHOW_V1\tfiles\n'
_lpeco_manager=$1
case "$_lpeco_manager" in
  system) set -- /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system ;;
  user) set -- "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user" "${XDG_RUNTIME_DIR:-/run/user/$(id -u 2>/dev/null)}/systemd/user" "$HOME/.local/share/systemd/user" /usr/local/share/systemd/user /usr/share/systemd/user ;;
  *) printf 'ERROR\tmanager\tinvalid manager\n' >&2; exit 64 ;;
esac
for _lpeco_root do
  for _lpeco_path in "$_lpeco_root"/*.service "$_lpeco_root"/*.timer "$_lpeco_root"/*.socket "$_lpeco_root"/*.path; do
    [ -f "$_lpeco_path" ] || [ -L "$_lpeco_path" ] || continue
    _lpeco_unit=${_lpeco_path##*/}
    printf 'UNIT\t%s\t%s\n' "$_lpeco_manager" "$_lpeco_unit"
    printf 'Id=%s\nFragmentPath=%s\n' "$_lpeco_unit" "$_lpeco_path"
    if [ "$_lpeco_manager" = user ]; then printf 'ManagerUID=%s\n' "$(id -u 2>/dev/null)"; fi
    printf 'END_UNIT\n'
  done
done`

const catScript = `_lpeco_manager=$1
case "$1" in system) _lpeco_scope=; _lpeco_manager_uid=0 ;; user) _lpeco_scope=--user; _lpeco_manager_uid=$(id -u 2>/dev/null) ;; *) exit 64 ;; esac
case "$2" in ''|-*) exit 64 ;; esac
printf 'LPECO_MANAGER\t%s\t%s\n' "$_lpeco_manager" "$_lpeco_manager_uid"
LC_ALL=C systemctl $_lpeco_scope cat --no-pager -- "$2"`

const unitFileCatScript = `_lpeco_manager=$1
case "$1" in
  system) _lpeco_manager_uid=0; set -- "$2" /lib/systemd/system /usr/lib/systemd/system /usr/local/lib/systemd/system /run/systemd/system /etc/systemd/system ;;
  user) _lpeco_manager_uid=$(id -u 2>/dev/null); set -- "$2" /usr/share/systemd/user /usr/local/share/systemd/user "$HOME/.local/share/systemd/user" "${XDG_RUNTIME_DIR:-/run/user/$(id -u 2>/dev/null)}/systemd/user" "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user" ;;
  *) exit 64 ;;
esac
printf 'LPECO_MANAGER\t%s\t%s\n' "$_lpeco_manager" "$_lpeco_manager_uid"
_lpeco_unit=$1
shift
case "$_lpeco_unit" in ''|-*|*/*) exit 64 ;; esac
for _lpeco_root do
  _lpeco_path="$_lpeco_root/$_lpeco_unit"
  if [ -f "$_lpeco_path" ]; then printf '# %s\n' "$_lpeco_path"; sed -n '1,$p' "$_lpeco_path" 2>/dev/null; fi
  for _lpeco_dropin in "$_lpeco_root/$_lpeco_unit.d"/*.conf; do
    [ -f "$_lpeco_dropin" ] || continue
    printf '# %s\n' "$_lpeco_dropin"
    sed -n '1,$p' "$_lpeco_dropin" 2>/dev/null
  done
done`

func ShowDefinition(manager string) probe.Definition {
	return probe.Definition{
		ID:              "systemd.show." + manager,
		Collector:       "systemd",
		Parser:          "systemd-show-v1",
		RedactionPolicy: "paths",
		SafetyClass:     model.PassiveRead,
		Requirements:    []probe.Requirement{probe.RequireSystemd},
		Variants: []probe.Variant{
			{ID: "systemctl", Command: adapter.Command{Script: showScript, Args: []string{manager}}, Requirements: []probe.Requirement{probe.CommandRequirement("systemctl")}},
			{ID: "unit-files", Command: adapter.Command{Script: unitFileInventoryScript, Args: []string{manager}}},
		},
		Timeout: 30 * time.Second, MaxOutput: 16 * 1024 * 1024,
		Produces: []string{"systemd_unit", "systemd_exec", "systemd_activation", "systemd_security"}, Idempotent: true,
	}
}

func CatDefinition(manager, unit string) probe.Definition {
	return probe.Definition{
		ID:              "systemd.cat." + manager + "." + unit,
		Collector:       "systemd",
		Parser:          "systemd-cat-v1",
		RedactionPolicy: "paths",
		SafetyClass:     model.PassiveRead,
		Requirements:    []probe.Requirement{probe.RequireSystemd},
		Variants: []probe.Variant{
			{ID: "systemctl", Command: adapter.Command{Script: catScript, Args: []string{manager, unit}}, Requirements: []probe.Requirement{probe.CommandRequirement("systemctl")}},
			{ID: "unit-files", Command: adapter.Command{Script: unitFileCatScript, Args: []string{manager, unit}}},
		},
		Timeout: 10 * time.Second, MaxOutput: 2 * 1024 * 1024,
		Produces: []string{"systemd_unit", "systemd_unit_source", "systemd_exec", "systemd_security"}, Idempotent: true,
	}
}

type Collector struct{}

func (Collector) ID() string { return "systemd" }

func (Collector) Assess(definition probe.Definition, variant probe.Variant, result adapter.ExecResult) collect.ObservationAssessment {
	assessment := collect.ObservationAssessment{Status: result.Status}
	if variant.ID != "systemctl" {
		return assessment
	}
	failed := result.Status != "" && result.Status != model.ProbeComplete
	if result.ExitCode != nil && *result.ExitCode != 0 {
		failed = true
	}
	switch definition.Parser {
	case "systemd-show-v1":
		failed = failed || !bytes.Contains(result.Stdout, []byte("\nUNIT\t")) || bytes.Contains(result.Stdout, []byte("CollectionError="))
	case "systemd-cat-v1":
		failed = failed || !bytes.Contains(result.Stdout, []byte("\n# /"))
	}
	if failed {
		assessment.Fallback = true
		if len(result.Stdout) > 0 || len(result.Stderr) > 0 {
			assessment.Status = model.ProbePartial
		} else {
			assessment.Status = model.ProbeUnavailable
		}
	}
	return assessment
}

func (Collector) Plan(profile model.HostProfile, discovery collect.Discovery) []probe.Definition {
	if !profile.SystemdRunning {
		return nil
	}
	definitions := []probe.Definition{ShowDefinition("system"), ShowDefinition("user")}
	unitNames := append([]string(nil), discovery.UnitNames...)
	sort.Strings(unitNames)
	for _, unit := range compactNonEmpty(unitNames) {
		definitions = append(definitions, CatDefinition("system", unit), CatDefinition("user", unit))
	}
	return definitions
}

func (Collector) Parse(definition probe.Definition, result adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
	switch definition.Parser {
	case "systemd-show-v1":
		units, diagnostics := ParseShow(result.Stdout, evidenceID)
		if len(units) == 0 {
			return []model.Fact{collectionStatusFact(definition, result, evidenceID, diagnostics)}, nil
		}
		normalized := Normalize(units, nil, currentManagerUID(units))
		normalized.Diagnostics = append(normalized.Diagnostics, diagnostics...)
		facts, err := Facts(normalized)
		if err != nil {
			return nil, err
		}
		if len(diagnostics) > 0 || result.Status != "" && result.Status != model.ProbeComplete {
			facts = append(facts, collectionStatusFact(definition, result, evidenceID, diagnostics))
		}
		return facts, nil
	case "systemd-cat-v1":
		manager, unit, err := catDefinitionParts(definition.ID)
		if err != nil {
			return nil, err
		}
		documents, diagnostics := ParseCat(unit, result.Stdout, evidenceID)
		if len(documents) == 0 {
			return []model.Fact{collectionStatusFact(definition, result, evidenceID, diagnostics)}, nil
		}
		managerUID := managerUIDFromCat(result.Stdout, manager)
		normalized := Normalize(nil, map[string][]DocumentSet{unit: {{Documents: documents, Complete: result.Status == model.ProbeComplete}}}, managerUID)
		applyScope(&normalized, manager, managerUID)
		normalized.Diagnostics = append(normalized.Diagnostics, diagnostics...)
		return Facts(normalized)
	default:
		return nil, fmt.Errorf("unsupported systemd parser %q", definition.Parser)
	}
}

func managerUIDFromCat(input []byte, manager string) int {
	if manager == "system" {
		return 0
	}
	firstLine := strings.SplitN(string(input), "\n", 2)[0]
	parts := strings.Split(firstLine, "\t")
	if len(parts) == 3 && parts[0] == "LPECO_MANAGER" && parts[1] == manager {
		if uid, err := strconv.Atoi(parts[2]); err == nil && uid >= 0 {
			return uid
		}
	}
	return -1
}

func applyScope(normalized *Normalized, manager string, managerUID int) {
	for index := range normalized.Units {
		normalized.Units[index].Manager = manager
		normalized.Units[index].ManagerUID = managerUID
		if manager == "user" {
			normalized.Units[index].UID = managerUID
			normalized.Units[index].GID = -1
			normalized.Units[index].User = ""
			normalized.Units[index].Group = ""
			normalized.Units[index].InventoryOnly = true
		}
	}
	for index := range normalized.Sources {
		normalized.Sources[index].Manager = manager
		normalized.Sources[index].ManagerUID = managerUID
	}
	for index := range normalized.Execs {
		normalized.Execs[index].Manager = manager
		normalized.Execs[index].ManagerUID = managerUID
	}
	for index := range normalized.Activations {
		normalized.Activations[index].Manager = manager
		normalized.Activations[index].ManagerUID = managerUID
	}
	for index := range normalized.Security {
		normalized.Security[index].Manager = manager
		normalized.Security[index].ManagerUID = managerUID
	}
}

type collectionStatus struct {
	ProbeID      string                `json:"probe_id"`
	Status       model.ProbeStatus     `json:"status"`
	Message      string                `json:"message"`
	Diagnostics  []CollectorDiagnostic `json:"diagnostics,omitempty"`
	MissingFacts []string              `json:"missing_facts"`
	EvidenceIDs  []string              `json:"evidence_ids"`
	Confidence   model.Confidence      `json:"confidence"`
}

func collectionStatusFact(definition probe.Definition, result adapter.ExecResult, evidenceID string, diagnostics []CollectorDiagnostic) model.Fact {
	status := result.Status
	if status == "" {
		status = model.ProbeUnavailable
	}
	message := strings.TrimSpace(string(result.Stderr))
	if message == "" && len(diagnostics) > 0 {
		message = diagnostics[0].Message
	}
	if len(message) > 512 {
		message = message[:512]
	}
	payload := collectionStatus{
		ProbeID: definition.ID, Status: status, Message: message, Diagnostics: diagnostics,
		MissingFacts: []string{"systemd runtime or unit-file facts unavailable"}, EvidenceIDs: []string{evidenceID}, Confidence: model.ConfidenceLow,
	}
	data, _ := json.Marshal(payload)
	id, _ := model.StableID("fact", struct {
		Kind string
		Data json.RawMessage
	}{"systemd_collection_status", data})
	return model.Fact{ID: id, Kind: "systemd_collection_status", SourceCollector: "systemd", EvidenceIDs: []string{evidenceID}, Confidence: model.ConfidenceLow, Data: data}
}

func currentManagerUID(units []RuntimeUnit) int {
	for _, unit := range units {
		if unit.Manager == "user" {
			return unit.ManagerUID
		}
	}
	return -1
}

func catDefinitionParts(id string) (string, string, error) {
	rest, found := strings.CutPrefix(id, "systemd.cat.")
	if !found {
		return "", "", fmt.Errorf("invalid systemd cat probe ID %q", id)
	}
	manager, unit, found := strings.Cut(rest, ".")
	if !found || (manager != "system" && manager != "user") || unit == "" {
		return "", "", fmt.Errorf("invalid systemd cat probe ID %q", id)
	}
	return manager, unit, nil
}

var _ collect.Collector = Collector{}
