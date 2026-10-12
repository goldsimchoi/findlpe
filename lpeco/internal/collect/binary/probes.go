package binary

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	pathcollect "github.com/normalone/lpeco/internal/collect/path"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

type PrivilegedBinaryFact struct {
	Path         string           `json:"path"`
	MajorMinor   string           `json:"major_minor"`
	Mode         uint32           `json:"mode"`
	UID          int              `json:"uid"`
	GID          int              `json:"gid"`
	SUID         bool             `json:"suid"`
	SGID         bool             `json:"sgid"`
	Capabilities []string         `json:"capabilities"`
	EvidenceIDs  []string         `json:"evidence_ids"`
	MissingFacts []string         `json:"missing_facts,omitempty"`
	Confidence   model.Confidence `json:"confidence"`
}

type WalkOptions struct {
	Roots    []string
	Excludes []string
	Limit    int
}

type WalkTarget struct {
	Root       string `json:"root"`
	MajorMinor string `json:"major_minor"`
	Limit      int    `json:"limit"`
}

const privilegedScript = `printf 'LPECO_PRIVILEGED_V1\n'
case "$2" in ''|*[!0-9]*) exit 64 ;; esac
_lpeco_root=$1; _lpeco_limit=$2; shift 2
_lpeco_hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
_lpeco_excluded() {
  _lpeco_candidate=$1; shift
  for _lpeco_prefix do
    case "$_lpeco_candidate" in "$_lpeco_prefix"|"$_lpeco_prefix"/*) return 0 ;; esac
  done
  return 1
}
_lpeco_count=0
find "$_lpeco_root" -xdev \
  \( -type d -exec sh -c '_lpeco_candidate=$1; shift; for _lpeco_prefix do case "$_lpeco_candidate" in "$_lpeco_prefix"|"$_lpeco_prefix"/*) exit 0;; esac; done; exit 1' lpeco-find {} /proc /sys /dev /run "$@" \; -prune \) -o \
  -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null |
while IFS= read -r _lpeco_path; do
  _lpeco_excluded "$_lpeco_path" "$@" && continue
  _lpeco_count=$((_lpeco_count + 1)); [ "$_lpeco_count" -le "$_lpeco_limit" ] || break
  _lpeco_meta=$(stat -c '%d:%i|%f|%u|%g' -- "$_lpeco_path" 2>/dev/null) || continue
  _lpeco_dev=${_lpeco_meta%%|*}; _lpeco_rest=${_lpeco_meta#*|}; _lpeco_mode=${_lpeco_rest%%|*}; _lpeco_rest=${_lpeco_rest#*|}; _lpeco_uid=${_lpeco_rest%%|*}; _lpeco_gid=${_lpeco_rest#*|}
  _lpeco_caps=$(getcap -n -- "$_lpeco_path" 2>/dev/null); _lpeco_caps=${_lpeco_caps#* }
  printf 'FILE\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(_lpeco_hex "$_lpeco_path")" "$_lpeco_dev" "$_lpeco_mode" "$_lpeco_uid" "$_lpeco_gid" "$(_lpeco_hex "$_lpeco_caps")"
done
if command -v getcap >/dev/null 2>&1; then
  _lpeco_cap_count=0
  find "$_lpeco_root" -xdev \
    \( -type d -exec sh -c '_lpeco_candidate=$1; shift; for _lpeco_prefix do case "$_lpeco_candidate" in "$_lpeco_prefix"|"$_lpeco_prefix"/*) exit 0;; esac; done; exit 1' lpeco-find {} /proc /sys /dev /run "$@" \; -prune \) -o \
    -type f -print 2>/dev/null |
  while IFS= read -r _lpeco_path; do
    _lpeco_excluded "$_lpeco_path" "$@" && continue
    _lpeco_cap_line=$(getcap -n -- "$_lpeco_path" 2>/dev/null)
    _lpeco_caps=${_lpeco_cap_line#"$_lpeco_path"}; _lpeco_caps=${_lpeco_caps# }
    [ -n "$_lpeco_caps" ] || continue
    _lpeco_cap_count=$((_lpeco_cap_count + 1)); [ "$_lpeco_cap_count" -le "$_lpeco_limit" ] || break
    _lpeco_meta=$(stat -c '%d:%i|%f|%u|%g' -- "$_lpeco_path" 2>/dev/null) || continue
    _lpeco_dev=${_lpeco_meta%%|*}; _lpeco_rest=${_lpeco_meta#*|}; _lpeco_mode=${_lpeco_rest%%|*}; _lpeco_rest=${_lpeco_rest#*|}; _lpeco_uid=${_lpeco_rest%%|*}; _lpeco_gid=${_lpeco_rest#*|}
    printf 'FILE\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(_lpeco_hex "$_lpeco_path")" "$_lpeco_dev" "$_lpeco_mode" "$_lpeco_uid" "$_lpeco_gid" "$(_lpeco_hex "$_lpeco_caps")"
  done
fi`

const elfReadelfScript = `[ -r "$1" ] || exit 75
printf 'SHEBANG='; sed -n '1p' -- "$1" 2>/dev/null | od -An -v -tx1 | tr -d ' \n'; printf '\n'
LC_ALL=C readelf -l -d -- "$1" 2>/dev/null && exit 0
_lpeco_magic=$(dd if="$1" bs=4 count=1 2>/dev/null | od -An -v -tx1 | tr -d ' \n')
[ "$_lpeco_magic" != 7f454c46 ] || exit 75
exit 0`
const elfObjdumpScript = `[ -r "$1" ] || exit 75
printf 'SHEBANG='; sed -n '1p' -- "$1" 2>/dev/null | od -An -v -tx1 | tr -d ' \n'; printf '\n'
LC_ALL=C objdump -p -- "$1" 2>/dev/null && exit 0
_lpeco_magic=$(dd if="$1" bs=4 count=1 2>/dev/null | od -An -v -tx1 | tr -d ' \n')
[ "$_lpeco_magic" != 7f454c46 ] || exit 75
exit 0`

const packageScript = `printf 'LPECO_PACKAGE_V1\nMANAGER\t%s\n' "$1"
_lpeco_status=0
case "$1" in
  dpkg) dpkg-query -S -- "$2" 2>/dev/null || _lpeco_status=$? ;;
  rpm) rpm -qf -- "$2" 2>/dev/null || _lpeco_status=$? ;;
  apk) apk info --who-owns -- "$2" 2>/dev/null || _lpeco_status=$? ;;
  *) exit 64 ;;
esac
case "$_lpeco_status" in
  0) ;;
  1) printf 'NOT_OWNED\n' ;;
  *) exit "$_lpeco_status" ;;
esac`

const packageUnknownScript = `printf 'LPECO_PACKAGE_V1\nMANAGER\tunknown\npackage manager unavailable\n'`

func PrivilegedDefinition(root string, limit int) probe.Definition {
	return PrivilegedDefinitionWithExcludes(root, nil, limit)
}

func PrivilegedDefinitionWithExcludes(root string, excludes []string, limit int) probe.Definition {
	if limit <= 0 {
		limit = 10000
	}
	excludes = unique(excludes)
	sort.Strings(excludes)
	arguments := []string{root, strconv.Itoa(limit)}
	arguments = append(arguments, excludes...)
	walkID, _ := model.StableID("walk", struct {
		Root     string
		Excludes []string
		Limit    int
	}{root, excludes, limit})
	return probe.Definition{
		ID: "binary.privileged." + walkID, Collector: "binary", Parser: "privileged-v1", RedactionPolicy: "paths", SafetyClass: model.PassiveRead,
		Variants: []probe.Variant{{ID: "find", Command: adapter.Command{Script: privilegedScript, Args: arguments}, Requirements: []probe.Requirement{probe.CommandRequirement("find")}}},
		Timeout:  60 * time.Second, MaxOutput: 16 * 1024 * 1024, Produces: []string{"privileged_binary"}, Idempotent: true,
	}
}

func ELFDefinition(path string) probe.Definition {
	return probe.Definition{
		ID: "binary.elf." + stableSuffix(path), Collector: "binary", Parser: "elf-text", RedactionPolicy: "paths", SafetyClass: model.PassiveRead,
		Variants: []probe.Variant{
			{ID: "readelf", Command: adapter.Command{Script: elfReadelfScript, Args: []string{path}}, Requirements: []probe.Requirement{probe.CommandRequirement("readelf")}},
			{ID: "objdump", Command: adapter.Command{Script: elfObjdumpScript, Args: []string{path}}, Requirements: []probe.Requirement{probe.CommandRequirement("objdump")}},
		},
		Timeout: 10 * time.Second, MaxOutput: 2 * 1024 * 1024, Produces: []string{"binary_dependency"}, Idempotent: true,
	}
}

func PackageDefinition(path string) probe.Definition {
	return probe.Definition{
		ID: "binary.package." + stableSuffix(path), Collector: "binary", Parser: "package-ownership", RedactionPolicy: "paths", SafetyClass: model.PassiveRead,
		Variants: []probe.Variant{
			{ID: "dpkg", Command: adapter.Command{Script: packageScript, Args: []string{"dpkg", path}}, Requirements: []probe.Requirement{probe.CommandRequirement("dpkg-query")}},
			{ID: "rpm", Command: adapter.Command{Script: packageScript, Args: []string{"rpm", path}}, Requirements: []probe.Requirement{probe.CommandRequirement("rpm")}},
			{ID: "apk", Command: adapter.Command{Script: packageScript, Args: []string{"apk", path}}, Requirements: []probe.Requirement{probe.CommandRequirement("apk")}},
			{ID: "unknown", Command: adapter.Command{Script: packageUnknownScript}},
		},
		Timeout: 10 * time.Second, MaxOutput: 512 * 1024, Produces: []string{"package_ownership"}, Idempotent: true,
	}
}

func ParsePrivilegedInventory(input []byte, evidenceID string) ([]PrivilegedBinaryFact, []Diagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	line := 0
	byPath := make(map[string]PrivilegedBinaryFact)
	var diagnostics []Diagnostic
	for scanner.Scan() {
		line++
		text := strings.TrimSuffix(scanner.Text(), "\r")
		if line == 1 {
			if text != "LPECO_PRIVILEGED_V1" {
				return nil, []Diagnostic{{Code: "unsupported-privileged-format", Message: "privileged inventory header is missing", EvidenceIDs: []string{evidenceID}}}
			}
			continue
		}
		parts := strings.Split(text, "\t")
		if len(parts) != 7 || parts[0] != "FILE" {
			if text != "" {
				diagnostics = append(diagnostics, Diagnostic{Code: "malformed-privileged-record", Message: fmt.Sprintf("line %d", line), EvidenceIDs: []string{evidenceID}})
			}
			continue
		}
		pathBytes, pathErr := hex.DecodeString(parts[1])
		mode, modeErr := strconv.ParseUint(parts[3], 16, 32)
		uid, uidErr := strconv.Atoi(parts[4])
		gid, gidErr := strconv.Atoi(parts[5])
		var capBytes []byte
		var capErr error
		if parts[6] != "-" {
			capBytes, capErr = hex.DecodeString(parts[6])
		}
		if pathErr != nil || modeErr != nil || uidErr != nil || gidErr != nil || capErr != nil {
			diagnostics = append(diagnostics, Diagnostic{Code: "invalid-privileged-record", Message: fmt.Sprintf("line %d", line), EvidenceIDs: []string{evidenceID}})
			continue
		}
		path := string(pathBytes)
		fact := byPath[path]
		fact.Path = path
		fact.MajorMinor = parts[2]
		fact.Mode = uint32(mode)
		fact.UID = uid
		fact.GID = gid
		fact.SUID = fact.Mode&0o4000 != 0
		fact.SGID = fact.Mode&0o2000 != 0
		if caps := strings.TrimSpace(string(capBytes)); caps != "" {
			for _, capability := range strings.Split(caps, ",") {
				capability = strings.TrimSpace(capability)
				if capability != "" && !contains(fact.Capabilities, capability) {
					fact.Capabilities = append(fact.Capabilities, capability)
				}
			}
		}
		fact.EvidenceIDs = []string{evidenceID}
		fact.Confidence = model.ConfidenceHigh
		byPath[path] = fact
	}
	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	values := make([]PrivilegedBinaryFact, 0, len(paths))
	for _, path := range paths {
		values = append(values, byPath[path])
	}
	return values, diagnostics
}

func PlanWalk(mounts []pathcollect.MountObservation, options WalkOptions) []WalkTarget {
	limit := options.Limit
	if limit <= 0 {
		limit = 10000
	}
	excludes := append([]string{"/proc", "/sys", "/dev", "/run"}, options.Excludes...)
	excluded := func(target string) bool {
		for _, prefix := range excludes {
			if pathWithin(target, prefix) {
				return true
			}
		}
		return false
	}
	ordered := append([]pathcollect.MountObservation(nil), mounts...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Bind != ordered[j].Bind {
			return !ordered[i].Bind
		}
		return ordered[i].MountPoint < ordered[j].MountPoint
	})
	eligible := make([]pathcollect.MountObservation, 0, len(ordered))
	for _, mount := range ordered {
		mount.MountPoint = filepath.Clean(mount.MountPoint)
		if mount.Pseudo || mount.Remote || excluded(mount.MountPoint) {
			continue
		}
		eligible = append(eligible, mount)
	}
	roots := unique(options.Roots)
	if len(roots) == 0 {
		roots = []string{"/"}
	}
	for index := range roots {
		roots[index] = filepath.Clean(roots[index])
	}
	sort.Slice(roots, func(i, j int) bool {
		if len(roots[i]) != len(roots[j]) {
			return len(roots[i]) < len(roots[j])
		}
		return roots[i] < roots[j]
	})
	containedRoots := make([]string, 0, len(roots))
	for _, root := range roots {
		if excluded(root) {
			continue
		}
		covered := false
		for _, existing := range containedRoots {
			if pathWithin(root, existing) {
				covered = true
				break
			}
		}
		if !covered {
			containedRoots = append(containedRoots, root)
		}
	}
	seenTargets := make(map[string]bool)
	seenFullDevices := make(map[string]bool)
	var targets []WalkTarget
	add := func(mount pathcollect.MountObservation, root string) {
		root = filepath.Clean(root)
		deviceKey := mount.MajorMinor + "|" + mount.Root
		if root == mount.MountPoint && seenFullDevices[deviceKey] {
			return
		}
		targetKey := deviceKey + "|" + root
		if seenTargets[targetKey] {
			return
		}
		seenTargets[targetKey] = true
		if root == mount.MountPoint {
			seenFullDevices[deviceKey] = true
		}
		targets = append(targets, WalkTarget{Root: root, MajorMinor: mount.MajorMinor, Limit: limit})
	}
	for _, root := range containedRoots {
		containing := -1
		for index, mount := range eligible {
			if pathWithin(root, mount.MountPoint) && (containing < 0 || len(mount.MountPoint) > len(eligible[containing].MountPoint)) {
				containing = index
			}
		}
		if containing >= 0 {
			add(eligible[containing], root)
		}
		for _, mount := range eligible {
			if pathWithin(mount.MountPoint, root) {
				add(mount, mount.MountPoint)
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Root != targets[j].Root {
			return targets[i].Root < targets[j].Root
		}
		return targets[i].MajorMinor < targets[j].MajorMinor
	})
	return targets
}

type Collector struct {
	WalkOptions WalkOptions
}

func (Collector) ID() string { return "binary" }

func (collector Collector) Plan(_ model.HostProfile, discovery collect.Discovery) []probe.Definition {
	definitions := []probe.Definition{SudoersDefinition(), SudoListDefinition()}
	if len(discovery.Mounts) > 0 {
		mounts := make([]pathcollect.MountObservation, 0, len(discovery.Mounts))
		for _, mount := range discovery.Mounts {
			mounts = append(mounts, pathcollect.MountObservation{
				ID: mount.ID, MajorMinor: mount.MajorMinor, Root: mount.Root, MountPoint: mount.MountPoint,
				Bind: mount.Bind, Remote: mount.Remote, Pseudo: mount.Pseudo,
			})
		}
		for _, target := range PlanWalk(mounts, collector.WalkOptions) {
			definitions = append(definitions, PrivilegedDefinitionWithExcludes(target.Root, collector.WalkOptions.Excludes, target.Limit))
		}
	} else {
		roots := unique(collector.WalkOptions.Roots)
		if len(roots) == 0 {
			roots = []string{"/"}
		}
		sort.Strings(roots)
		for _, root := range roots {
			definitions = append(definitions, PrivilegedDefinitionWithExcludes(root, collector.WalkOptions.Excludes, collector.WalkOptions.Limit))
		}
	}
	paths := append([]string(nil), discovery.ReferencedPaths...)
	sort.Strings(paths)
	paths = unique(paths)
	for _, path := range paths {
		definitions = append(definitions, ELFDefinition(path), PackageDefinition(path))
	}
	return definitions
}

func (Collector) Parse(definition probe.Definition, result adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
	switch definition.Parser {
	case "sudoers-v1":
		return marshalFacts("delegation", ParseSudoersProbe(result.Stdout, evidenceID), evidenceID)
	case "sudo-list":
		return marshalFacts("delegation", ParseSudoList(result.Stdout, evidenceID), evidenceID)
	case "privileged-v1":
		values, _ := ParsePrivilegedInventory(result.Stdout, evidenceID)
		return marshalFacts("privileged_binary", values, evidenceID)
	case "elf-text":
		path := firstCommandPath(definition)
		values, _ := ParseELF(path, result.Stdout, evidenceID)
		return marshalFacts("binary_dependency", values, evidenceID)
	case "package-ownership":
		path := firstCommandPath(definition)
		value := ParsePackageProbe(path, result.Stdout, evidenceID)
		return marshalFacts("package_ownership", []PackageOwnershipFact{value}, evidenceID)
	default:
		return nil, fmt.Errorf("unsupported binary parser %q", definition.Parser)
	}
}

func marshalFacts(kind string, values any, evidenceID string) ([]model.Fact, error) {
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
		var envelope struct {
			EvidenceIDs []string         `json:"evidence_ids"`
			Confidence  model.Confidence `json:"confidence"`
		}
		_ = json.Unmarshal(data, &envelope)
		if len(envelope.EvidenceIDs) == 0 {
			envelope.EvidenceIDs = []string{evidenceID}
		}
		if envelope.Confidence == "" {
			envelope.Confidence = model.ConfidenceLow
		}
		facts = append(facts, model.Fact{ID: id, Kind: kind, SourceCollector: "binary", EvidenceIDs: envelope.EvidenceIDs, Confidence: envelope.Confidence, Data: data})
	}
	return facts, nil
}

func stableSuffix(value string) string {
	id, _ := model.StableID("target", value)
	return id
}

func firstCommandPath(definition probe.Definition) string {
	for _, variant := range definition.Variants {
		if len(variant.Command.Args) == 1 {
			return variant.Command.Args[0]
		}
		if len(variant.Command.Args) >= 2 {
			return variant.Command.Args[len(variant.Command.Args)-1]
		}
	}
	return ""
}

func pathWithin(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	return path == root || root == "/" || strings.HasPrefix(path, root+"/")
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func unique(values []string) []string {
	var result []string
	for _, value := range values {
		if value != "" && !contains(result, value) {
			result = append(result, value)
		}
	}
	return result
}

var _ collect.Collector = Collector{}
