package systemd

import (
	"encoding/json"
	"fmt"
	"sort"
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

const unitFileInventoryScript = `printf 'LPECO_SYSTEMD_SHOW_V1\n'
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
    printf 'Id=%s\nFragmentPath=%s\nEND_UNIT\n' "$_lpeco_unit" "$_lpeco_path"
  done
done`

const catScript = `case "$1" in system) _lpeco_scope= ;; user) _lpeco_scope=--user ;; *) exit 64 ;; esac
case "$2" in ''|-*) exit 64 ;; esac
LC_ALL=C systemctl $_lpeco_scope cat --no-pager -- "$2"`

const unitFileCatScript = `case "$1" in
  system) set -- "$2" /lib/systemd/system /usr/lib/systemd/system /usr/local/lib/systemd/system /run/systemd/system /etc/systemd/system ;;
  user) set -- "$2" /usr/share/systemd/user /usr/local/share/systemd/user "$HOME/.local/share/systemd/user" "${XDG_RUNTIME_DIR:-/run/user/$(id -u 2>/dev/null)}/systemd/user" "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user" ;;
  *) exit 64 ;;
esac
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
		normalized := Normalize(nil, map[string][]DocumentSet{unit: {{Documents: documents, Complete: result.Status == model.ProbeComplete}}}, -1)
		if manager == "user" {
			for index := range normalized.Units {
				normalized.Units[index].Manager = "user"
				normalized.Units[index].InventoryOnly = true
			}
		}
		normalized.Diagnostics = append(normalized.Diagnostics, diagnostics...)
		return Facts(normalized)
	default:
		return nil, fmt.Errorf("unsupported systemd parser %q", definition.Parser)
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
		if unit.Manager == "user" && unit.ManagerUID != 0 {
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
