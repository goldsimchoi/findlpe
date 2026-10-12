package path

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

const statScript = `printf 'LPECO_PATH_STAT_V1\n'
_lpeco_hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
_lpeco_emit() {
  _lpeco_path=$1
  _lpeco_meta=$(LC_ALL=C stat -c '%d|%i|%f|%u|%g|%F' -- "$_lpeco_path" 2>/dev/null) || { printf 'ERROR\t%s\tstat unavailable\n' "$(_lpeco_hex "$_lpeco_path")"; return; }
  _lpeco_device=${_lpeco_meta%%|*}; _lpeco_rest=${_lpeco_meta#*|}
  _lpeco_inode=${_lpeco_rest%%|*}; _lpeco_rest=${_lpeco_rest#*|}
  _lpeco_mode=${_lpeco_rest%%|*}; _lpeco_rest=${_lpeco_rest#*|}
  _lpeco_uid=${_lpeco_rest%%|*}; _lpeco_rest=${_lpeco_rest#*|}
  _lpeco_gid=${_lpeco_rest%%|*}; _lpeco_kind=${_lpeco_rest#*|}
  _lpeco_link=
  if [ -L "$_lpeco_path" ]; then _lpeco_link=$(readlink -- "$_lpeco_path" 2>/dev/null); fi
  printf 'STAT\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(_lpeco_hex "$_lpeco_path")" "$_lpeco_device" "$_lpeco_inode" "$_lpeco_mode" "$_lpeco_uid" "$_lpeco_gid" "$_lpeco_kind" "$(_lpeco_hex "$_lpeco_link")"
}
_lpeco_walk() {
  _lpeco_path=$1
  while :; do
    _lpeco_emit "$_lpeco_path"
    [ "$_lpeco_path" = / ] && break
    _lpeco_path=${_lpeco_path%/*}; [ -n "$_lpeco_path" ] || _lpeco_path=/
  done
}
case "$1" in /*) _lpeco_input=$1 ;; *) _lpeco_input="$(pwd -P)/$1" ;; esac
_lpeco_walk "$_lpeco_input"
_lpeco_resolved=$(readlink -f -- "$_lpeco_input" 2>/dev/null) || _lpeco_resolved=
if [ -n "$_lpeco_resolved" ] && [ "$_lpeco_resolved" != "$_lpeco_input" ]; then _lpeco_walk "$_lpeco_resolved"; fi`

const aclScript = `printf 'LPECO_PATH_ACL_V1\n'
_lpeco_hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
_lpeco_emit() {
  _lpeco_path=$1
  _lpeco_acl=$(LC_ALL=C getfacl -cpn -- "$_lpeco_path" 2>/dev/null) || { printf 'ERROR\t%s\tgetfacl unavailable\n' "$(_lpeco_hex "$_lpeco_path")"; return; }
  printf 'ACL\t%s\n' "$(_lpeco_hex "$_lpeco_path")"
  printf '%s\n' "$_lpeco_acl"
  printf 'END_ACL\n'
}
_lpeco_walk() {
  _lpeco_path=$1
  while :; do
    _lpeco_emit "$_lpeco_path"
    [ "$_lpeco_path" = / ] && break
    _lpeco_path=${_lpeco_path%/*}; [ -n "$_lpeco_path" ] || _lpeco_path=/
  done
}
case "$1" in /*) _lpeco_input=$1 ;; *) _lpeco_input="$(pwd -P)/$1" ;; esac
_lpeco_walk "$_lpeco_input"
_lpeco_resolved=$(readlink -f -- "$_lpeco_input" 2>/dev/null) || _lpeco_resolved=
if [ -n "$_lpeco_resolved" ] && [ "$_lpeco_resolved" != "$_lpeco_input" ]; then _lpeco_walk "$_lpeco_resolved"; fi`

const aclUnavailableScript = `printf 'LPECO_PATH_ACL_V1\n'
_lpeco_hex=$(printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n')
printf 'ERROR\t%s\tgetfacl command unavailable\n' "$_lpeco_hex"`

const mountInfoScript = `sed -n '1,$p' /proc/self/mountinfo 2>/dev/null`

func MountInfoDefinition() probe.Definition {
	return probe.Definition{
		ID: "path.mountinfo", Collector: "path", Parser: "mountinfo", RedactionPolicy: "paths", SafetyClass: model.PassiveRead,
		Variants: []probe.Variant{{ID: "proc", Command: adapter.Command{Script: mountInfoScript}}},
		Timeout:  5 * time.Second, MaxOutput: 4 * 1024 * 1024, Produces: []string{"mount"}, Idempotent: true,
	}
}

func StatDefinition(target string) probe.Definition {
	return probe.Definition{
		ID: "path.stat." + pathProbeID(target), Collector: "path", Parser: "path-stat-v1", RedactionPolicy: "paths", SafetyClass: model.PassiveRead,
		Variants: []probe.Variant{{ID: "stat", Command: adapter.Command{Script: statScript, Args: []string{target}}, Requirements: []probe.Requirement{probe.CommandRequirement("stat")}}},
		Timeout:  10 * time.Second, MaxOutput: 2 * 1024 * 1024, Produces: []string{"path_stat"}, Idempotent: true,
	}
}

func ACLDefinition(target string) probe.Definition {
	return probe.Definition{
		ID: "path.acl." + pathProbeID(target), Collector: "path", Parser: "path-acl-v1", RedactionPolicy: "paths", SafetyClass: model.PassiveRead,
		Variants: []probe.Variant{
			{ID: "getfacl", Command: adapter.Command{Script: aclScript, Args: []string{target}}, Requirements: []probe.Requirement{probe.CommandRequirement("getfacl")}},
			{ID: "unavailable", Command: adapter.Command{Script: aclUnavailableScript, Args: []string{target}}},
		},
		Timeout: 10 * time.Second, MaxOutput: 2 * 1024 * 1024, Produces: []string{"path_acl"}, Idempotent: true,
	}
}

type Collector struct{}

func (Collector) ID() string { return "path" }

func (Collector) Plan(_ model.HostProfile, discovery collect.Discovery) []probe.Definition {
	definitions := []probe.Definition{MountInfoDefinition()}
	paths := uniqueStrings(discovery.ReferencedPaths)
	sort.Strings(paths)
	for _, target := range paths {
		definitions = append(definitions, StatDefinition(target), ACLDefinition(target))
	}
	return definitions
}

func (Collector) Parse(definition probe.Definition, result adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
	switch definition.Parser {
	case "path-stat-v1":
		values, _ := ParseStat(result.Stdout, evidenceID)
		return pathFacts("path_stat", values, evidenceID)
	case "path-acl-v1":
		values, _ := ParseACL(result.Stdout, evidenceID)
		return pathFacts("path_acl", values, evidenceID)
	case "mountinfo":
		values, _ := ParseMountInfo(result.Stdout, evidenceID)
		return pathFacts("mount", values, evidenceID)
	default:
		return nil, fmt.Errorf("unsupported path parser %q", definition.Parser)
	}
}

func pathFacts(kind string, values any, evidenceID string) ([]model.Fact, error) {
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(encoded, &entries); err != nil {
		return nil, err
	}
	facts := make([]model.Fact, 0, len(entries))
	for _, data := range entries {
		id, err := model.StableID("fact", struct {
			Kind string
			Data json.RawMessage
		}{kind, data})
		if err != nil {
			return nil, err
		}
		facts = append(facts, model.Fact{ID: id, Kind: kind, SourceCollector: "path", EvidenceIDs: []string{evidenceID}, Confidence: model.ConfidenceHigh, Data: data})
	}
	return facts, nil
}

func pathProbeID(target string) string {
	id, err := model.StableID("path", target)
	if err != nil {
		return "invalid"
	}
	return id
}

var _ collect.Collector = Collector{}
