package packageinfo

import (
	"fmt"
	pathpkg "path"
	"sort"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

const ownershipScript = `printf 'LPECO_PACKAGE_OWNERSHIP_V1\n'
_lpeco_manager=$1; shift
_lpeco_hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
_lpeco_query() {
  _lpeco_kind=$1; _lpeco_target=$2; _lpeco_status=0; _lpeco_output=
  case "$_lpeco_manager" in
    dpkg) _lpeco_output=$(LC_ALL=C dpkg-query -S -- "$_lpeco_target" 2>/dev/null) || _lpeco_status=$? ;;
    rpm) _lpeco_output=$(LC_ALL=C rpm -qf -- "$_lpeco_target" 2>/dev/null) || _lpeco_status=$? ;;
    apk) _lpeco_output=$(LC_ALL=C apk info --who-owns -- "$_lpeco_target" 2>/dev/null) || _lpeco_status=$? ;;
    *) _lpeco_status=127 ;;
  esac
  printf 'QUERY\t%s\t%s\t%s\n' "$_lpeco_kind" "$_lpeco_status" "$(_lpeco_hex "$_lpeco_output")"
}
for _lpeco_path do
  _lpeco_resolved=$(readlink -f -- "$_lpeco_path" 2>/dev/null) || _lpeco_resolved=
  printf 'BEGIN\t%s\t%s\t%s\n' "$(_lpeco_hex "$_lpeco_path")" "$(_lpeco_hex "$_lpeco_resolved")" "$_lpeco_manager"
  _lpeco_query observed "$_lpeco_path"
  if [ -n "$_lpeco_resolved" ] && [ "$_lpeco_resolved" != "$_lpeco_path" ]; then _lpeco_query resolved "$_lpeco_resolved"; fi
  printf 'END\n'
done`

const metadataScript = `printf 'LPECO_PACKAGE_METADATA_V1\n'
_lpeco_manager=$1; shift
_lpeco_hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
for _lpeco_package do
  _lpeco_status=0; _lpeco_output=
  case "$_lpeco_manager" in
    dpkg) _lpeco_output=$(LC_ALL=C dpkg-query -W -f='${Status}\t${binary:Package}\t${Architecture}\t${Version}\t${source:Package}\t${source:Version}\n' -- "$_lpeco_package" 2>/dev/null) || _lpeco_status=$? ;;
    *) _lpeco_status=127 ;;
  esac
  printf 'RECORD\t%s\t%s\t%s\t%s\n' "$(_lpeco_hex "$_lpeco_package")" "$_lpeco_manager" "$_lpeco_status" "$(_lpeco_hex "$_lpeco_output")"
done`

type Collector struct {
	MaxItems int
}

func (Collector) ID() string { return "packageinfo" }

func (Collector) Plan(model.HostProfile, collect.Discovery) []probe.Definition { return nil }

func (Collector) Parse(definition probe.Definition, result adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
	switch definition.Parser {
	case "package-ownership-v1":
		values, diagnostics := ParseOwnership(result.Stdout, evidenceID)
		if len(values) == 0 && len(diagnostics) > 0 {
			return nil, fmt.Errorf("parse package ownership: %s", diagnostics[0].Code)
		}
		return marshalFacts("package_ownership", values, evidenceID)
	case "package-metadata-v1":
		values, diagnostics := ParseMetadata(result.Stdout, evidenceID)
		if len(values) == 0 && len(diagnostics) > 0 {
			return nil, fmt.Errorf("parse package metadata: %s", diagnostics[0].Code)
		}
		return marshalFacts("installed_package", values, evidenceID)
	default:
		return nil, fmt.Errorf("unsupported package parser %q", definition.Parser)
	}
}

func (collector Collector) PlanOwnership(_ model.HostProfile, paths []string, capabilities adapter.Capabilities) Plan {
	items, invalid := normalizedPaths(paths)
	requested := len(items) + invalid
	limit := collector.maxItems()
	omitted := invalid
	if len(items) > limit {
		omitted += len(items) - limit
		items = items[:limit]
	}
	definitions, tooLarge := batchStrings(items, capabilities.MaxCommandBytes, func(batch []string) probe.Definition {
		return ownershipDefinition(batch, capabilities.MaxOutputBytes)
	})
	return Plan{Definitions: definitions, Requested: requested, Omitted: omitted + tooLarge}
}

func (collector Collector) PlanMetadata(_ model.HostProfile, requests []Request, capabilities adapter.Capabilities) Plan {
	values, invalid := normalizedRequests(requests)
	requested := len(values) + invalid
	limit := collector.maxItems()
	omitted := invalid
	if len(values) > limit {
		omitted += len(values) - limit
		values = values[:limit]
	}
	groups := make(map[string][]string)
	var managers []string
	for _, request := range values {
		if _, exists := groups[request.Manager]; !exists {
			managers = append(managers, request.Manager)
		}
		groups[request.Manager] = append(groups[request.Manager], request.Package)
	}
	sort.Strings(managers)
	var definitions []probe.Definition
	for _, manager := range managers {
		planned, tooLarge := batchStrings(groups[manager], capabilities.MaxCommandBytes, func(batch []string) probe.Definition {
			return metadataDefinition(manager, batch, capabilities.MaxOutputBytes)
		})
		definitions = append(definitions, planned...)
		omitted += tooLarge
	}
	return Plan{Definitions: definitions, Requested: requested, Omitted: omitted}
}

func (collector Collector) maxItems() int {
	if collector.MaxItems <= 0 {
		return DefaultMaxItems
	}
	return collector.MaxItems
}

func ownershipDefinition(paths []string, outputLimit int) probe.Definition {
	variants := []probe.Variant{
		packageVariant("dpkg", ownershipScript, paths, "dpkg-query"),
		packageVariant("rpm", ownershipScript, paths, "rpm"),
		packageVariant("apk", ownershipScript, paths, "apk"),
		packageVariant("unknown", ownershipScript, paths, ""),
	}
	id, _ := model.StableID("package-ownership", paths)
	return probe.Definition{
		ID: id, Collector: "packageinfo", Parser: "package-ownership-v1", RedactionPolicy: "paths", SafetyClass: model.PassiveRead,
		Variants: variants, Timeout: 10 * time.Second, MaxOutput: boundedOutput(outputLimit), Produces: []string{"package_ownership"}, Idempotent: true,
	}
}

func metadataDefinition(manager string, packages []string, outputLimit int) probe.Definition {
	variants := []probe.Variant{}
	if manager == "dpkg" || manager == "rpm" || manager == "apk" {
		command := map[string]string{"dpkg": "dpkg-query", "rpm": "rpm", "apk": "apk"}[manager]
		variants = append(variants, packageVariant(manager, metadataScript, packages, command))
	}
	variants = append(variants, packageVariant("unknown", metadataScript, packages, ""))
	id, _ := model.StableID("package-metadata", struct {
		Manager  string
		Packages []string
	}{manager, packages})
	return probe.Definition{
		ID: id, Collector: "packageinfo", Parser: "package-metadata-v1", RedactionPolicy: "package-metadata", SafetyClass: model.PassiveRead,
		Variants: variants, Timeout: 10 * time.Second, MaxOutput: boundedOutput(outputLimit), Produces: []string{"installed_package"}, Idempotent: true,
	}
}

func packageVariant(id, script string, values []string, command string) probe.Variant {
	args := make([]string, 0, len(values)+1)
	args = append(args, id)
	args = append(args, values...)
	variant := probe.Variant{ID: id, Command: adapter.Command{Script: script, Args: args}}
	if command != "" {
		variant.Requirements = []probe.Requirement{probe.CommandRequirement(command)}
	}
	return variant
}

func batchStrings(values []string, maxCommand int, build func([]string) probe.Definition) ([]probe.Definition, int) {
	if maxCommand <= 0 {
		maxCommand = 64 * 1024
	}
	var definitions []probe.Definition
	var batch []string
	omitted := 0
	for _, value := range values {
		candidate := append(append([]string(nil), batch...), value)
		if definitionFits(build(candidate), maxCommand) {
			batch = candidate
			continue
		}
		if len(batch) > 0 {
			definitions = append(definitions, build(batch))
			batch = nil
			if definitionFits(build([]string{value}), maxCommand) {
				batch = []string{value}
				continue
			}
		}
		omitted++
	}
	if len(batch) > 0 {
		definitions = append(definitions, build(batch))
	}
	return definitions, omitted
}

func definitionFits(definition probe.Definition, maxCommand int) bool {
	for _, variant := range definition.Variants {
		rendered, err := adapter.RenderPOSIX(variant.Command)
		if err != nil || len(rendered) > maxCommand {
			return false
		}
	}
	return true
}

func normalizedPaths(values []string) ([]string, int) {
	set := make(map[string]bool, len(values))
	invalid := 0
	for _, value := range values {
		if value == "" || strings.IndexByte(value, 0) >= 0 {
			invalid++
			continue
		}
		set[pathpkg.Clean(value)] = true
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, invalid
}

func normalizedRequests(values []Request) ([]Request, int) {
	byKey := make(map[string]Request, len(values))
	invalid := 0
	for _, value := range values {
		if value.Manager == "" {
			value.Manager = "dpkg"
		}
		if value.Package == "" || strings.IndexByte(value.Package, 0) >= 0 || strings.IndexByte(value.Manager, 0) >= 0 {
			invalid++
			continue
		}
		key := value.Manager + "\x00" + value.Package + "\x00" + value.Architecture
		if existing, ok := byKey[key]; ok {
			existing.Paths = uniqueStrings(append(existing.Paths, value.Paths...))
			existing.EvidenceIDs = uniqueStrings(append(existing.EvidenceIDs, value.EvidenceIDs...))
			byKey[key] = existing
			continue
		}
		value.Paths = uniqueStrings(value.Paths)
		value.EvidenceIDs = uniqueStrings(value.EvidenceIDs)
		byKey[key] = value
	}
	result := make([]Request, 0, len(byKey))
	for _, value := range byKey {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		left := result[i].Manager + "\x00" + result[i].Package + "\x00" + result[i].Architecture
		right := result[j].Manager + "\x00" + result[j].Package + "\x00" + result[j].Architecture
		return left < right
	})
	return result, invalid
}

func uniqueStrings(values []string) []string {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = true
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func boundedOutput(adapterLimit int) int {
	const packageLimit = 8 * 1024 * 1024
	if adapterLimit > 0 && adapterLimit < packageLimit {
		return adapterLimit
	}
	return packageLimit
}

var _ collect.Collector = Collector{}
