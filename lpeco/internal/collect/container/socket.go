package container

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

type Diagnostic struct {
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	Path        string   `json:"path,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type AdminSocketFact struct {
	Path         string           `json:"path"`
	Daemon       string           `json:"daemon"`
	DaemonUID    int              `json:"daemon_uid"`
	GID          int              `json:"gid"`
	Mode         uint32           `json:"mode"`
	WriteAccess  bool             `json:"write_access"`
	ACLSummary   string           `json:"acl_summary,omitempty"`
	EvidenceIDs  []string         `json:"evidence_ids"`
	MissingFacts []string         `json:"missing_facts,omitempty"`
	Confidence   model.Confidence `json:"confidence"`
}

const socketScript = `printf 'LPECO_ADMIN_SOCKET_V1\n'
_lpeco_hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
for _lpeco_spec in docker:/run/docker.sock docker:/var/run/docker.sock containerd:/run/containerd/containerd.sock cri-o:/var/run/crio/crio.sock podman:/run/podman/podman.sock lxd:/var/snap/lxd/common/lxd/unix.socket; do
  _lpeco_daemon=${_lpeco_spec%%:*}; _lpeco_path=${_lpeco_spec#*:}
  [ -S "$_lpeco_path" ] || continue
  _lpeco_meta=$(stat -c '%u|%g|%f' -- "$_lpeco_path" 2>/dev/null) || continue
  _lpeco_uid=${_lpeco_meta%%|*}; _lpeco_rest=${_lpeco_meta#*|}; _lpeco_gid=${_lpeco_rest%%|*}; _lpeco_mode=${_lpeco_rest#*|}
  _lpeco_access=0; [ -w "$_lpeco_path" ] && _lpeco_access=1
  _lpeco_acl=$(getfacl -cpn -- "$_lpeco_path" 2>/dev/null)
  printf 'SOCKET\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(_lpeco_hex "$_lpeco_path")" "$(_lpeco_hex "$_lpeco_daemon")" "$_lpeco_uid" "$_lpeco_gid" "$_lpeco_mode" "$_lpeco_access" "$(_lpeco_hex "$_lpeco_acl")"
done`

func SocketDefinition() probe.Definition {
	return probe.Definition{
		ID: "container.admin-sockets", Collector: "container", Parser: "admin-socket-v1", RedactionPolicy: "paths", SafetyClass: model.PassiveRead,
		Variants: []probe.Variant{{ID: "unix-mode-access", Command: adapter.Command{Script: socketScript}, Requirements: []probe.Requirement{probe.CommandRequirement("stat")}}},
		Timeout:  10 * time.Second, MaxOutput: 2 * 1024 * 1024, Produces: []string{"admin_socket"}, Idempotent: true,
	}
}

func ParseSocketInventory(input []byte, evidenceID string) ([]AdminSocketFact, []Diagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	var facts []AdminSocketFact
	var diagnostics []Diagnostic
	for scanner.Scan() {
		line++
		text := strings.TrimSuffix(scanner.Text(), "\r")
		if line == 1 {
			if text != "LPECO_ADMIN_SOCKET_V1" {
				return nil, []Diagnostic{{Code: "unsupported-socket-format", Message: "admin socket framing header is missing", EvidenceIDs: []string{evidenceID}}}
			}
			continue
		}
		parts := strings.Split(text, "\t")
		if len(parts) > 0 && parts[0] == "GROUP" {
			continue
		}
		if len(parts) != 7 && len(parts) != 8 {
			if text != "" {
				diagnostics = append(diagnostics, Diagnostic{Code: "malformed-socket-record", Message: fmt.Sprintf("line %d", line), EvidenceIDs: []string{evidenceID}})
			}
			continue
		}
		pathBytes, pathErr := hex.DecodeString(parts[1])
		daemonBytes, daemonErr := hex.DecodeString(parts[2])
		uid, uidErr := strconv.Atoi(parts[3])
		gid, gidErr := strconv.Atoi(parts[4])
		mode, modeErr := strconv.ParseUint(parts[5], 16, 32)
		access := parts[6] == "1"
		acl := ""
		var aclErr error
		if len(parts) == 8 {
			var aclBytes []byte
			aclBytes, aclErr = hex.DecodeString(parts[7])
			acl = string(aclBytes)
		}
		if pathErr != nil || daemonErr != nil || uidErr != nil || gidErr != nil || modeErr != nil || aclErr != nil {
			diagnostics = append(diagnostics, Diagnostic{Code: "invalid-socket-record", Message: fmt.Sprintf("line %d", line), EvidenceIDs: []string{evidenceID}})
			continue
		}
		if uint32(mode)&0o170000 != 0o140000 {
			diagnostics = append(diagnostics, Diagnostic{Code: "not-a-unix-socket", Message: fmt.Sprintf("line %d", line), Path: string(pathBytes), EvidenceIDs: []string{evidenceID}})
			continue
		}
		if !access {
			continue
		}
		fact := AdminSocketFact{
			Path: string(pathBytes), Daemon: string(daemonBytes), DaemonUID: uid, GID: gid, Mode: uint32(mode), WriteAccess: true,
			ACLSummary: acl, EvidenceIDs: []string{evidenceID}, Confidence: model.ConfidenceHigh,
		}
		if acl == "" {
			fact.MissingFacts = append(fact.MissingFacts, "ACL details unavailable; direct access check succeeded")
		}
		facts = append(facts, fact)
	}
	if err := scanner.Err(); err != nil {
		diagnostics = append(diagnostics, Diagnostic{Code: "socket-read-error", Message: err.Error(), EvidenceIDs: []string{evidenceID}})
	}
	return facts, diagnostics
}

type Collector struct{}

func (Collector) ID() string { return "container" }

func (Collector) Plan(model.HostProfile, collect.Discovery) []probe.Definition {
	return []probe.Definition{SocketDefinition()}
}

func (Collector) Parse(_ probe.Definition, result adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
	values, _ := ParseSocketInventory(result.Stdout, evidenceID)
	facts := make([]model.Fact, 0, len(values))
	for _, value := range values {
		data, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		id, err := model.StableID("fact", struct {
			Kind string
			Data json.RawMessage
		}{"admin_socket", data})
		if err != nil {
			return nil, err
		}
		facts = append(facts, model.Fact{ID: id, Kind: "admin_socket", SourceCollector: "container", EvidenceIDs: value.EvidenceIDs, Confidence: value.Confidence, Data: data})
	}
	return facts, nil
}

var _ collect.Collector = Collector{}
