package packageinfo

import (
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

func TestOwnershipPlanPreservesHostileArgumentsAndFraming(t *testing.T) {
	paths := []string{
		"/tmp/space name", "/tmp/single'quote", "/tmp/tab\tname", "/tmp/new\nline",
		"/tmp/$()", "/tmp/semi;colon", "-leading",
	}
	collector := Collector{MaxItems: 4096}
	plan := collector.PlanOwnership(model.HostProfile{AvailableCommands: map[string]bool{"dpkg-query": true}}, paths, adapter.Capabilities{MaxCommandBytes: 64 * 1024, MaxOutputBytes: 4 * 1024 * 1024})
	if plan.Omitted != 0 || plan.Requested != len(paths) || len(plan.Definitions) == 0 {
		t.Fatalf("plan = %#v", plan)
	}

	var gotArgs []string
	var roundTripped []string
	for _, definition := range plan.Definitions {
		assertPackageDefinition(t, definition, 64*1024)
		unknown := variantByID(t, definition, "unknown")
		gotArgs = append(gotArgs, unknown.Command.Args[1:]...)
		command := exec.Command("sh", append([]string{"-c", unknown.Command.Script, "lpeco"}, unknown.Command.Args...)...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("unknown ownership probe: %v\n%s", err, output)
		}
		facts, diagnostics := ParseOwnership(output, "e-hostile")
		if len(diagnostics) != 0 {
			t.Fatalf("hostile diagnostics = %#v", diagnostics)
		}
		for _, fact := range facts {
			roundTripped = append(roundTripped, fact.Path)
		}
	}
	want := append([]string(nil), paths...)
	sort.Strings(want)
	if !reflect.DeepEqual(gotArgs, want) || !reflect.DeepEqual(roundTripped, want) {
		t.Fatalf("hostile args/roundtrip\nargs: %#v\nfacts: %#v\nwant: %#v", gotArgs, roundTripped, want)
	}
}

func TestOwnershipPlanBoundsAndSplitsByRenderedCommandSize(t *testing.T) {
	paths := make([]string, 0, 4097)
	for index := 4096; index >= 0; index-- {
		paths = append(paths, "/opt/lpeco/"+strconv.Itoa(index)+"/a path with padding")
	}
	const maxCommand = 4096
	plan := (Collector{MaxItems: 4096}).PlanOwnership(model.HostProfile{}, paths, adapter.Capabilities{MaxCommandBytes: maxCommand})
	if plan.Requested != 4097 || plan.Omitted != 1 || len(plan.Definitions) < 2 {
		t.Fatalf("bounded plan = requested %d omitted %d definitions %d", plan.Requested, plan.Omitted, len(plan.Definitions))
	}
	var planned []string
	for _, definition := range plan.Definitions {
		assertPackageDefinition(t, definition, maxCommand)
		planned = append(planned, variantByID(t, definition, "unknown").Command.Args[1:]...)
	}
	if len(planned) != 4096 || !sort.StringsAreSorted(planned) {
		t.Fatalf("planned path count/order = %d/%v", len(planned), sort.StringsAreSorted(planned))
	}
	for index := 1; index < len(planned); index++ {
		if planned[index-1] == planned[index] {
			t.Fatalf("duplicate planned path %q", planned[index])
		}
	}
}

func TestMetadataPlanDeduplicatesAndPreservesPackageArguments(t *testing.T) {
	requests := []Request{
		{Manager: "dpkg", Package: "libc6:amd64", Architecture: "amd64"},
		{Manager: "dpkg", Package: "libc6:amd64", Architecture: "amd64"},
		{Manager: "dpkg", Package: "odd package'$(x);\n:amd64", Architecture: "amd64"},
	}
	plan := (Collector{MaxItems: 4096}).PlanMetadata(model.HostProfile{}, requests, adapter.Capabilities{MaxCommandBytes: 64 * 1024})
	if plan.Requested != 2 || plan.Omitted != 0 || len(plan.Definitions) != 1 {
		t.Fatalf("metadata plan = %#v", plan)
	}
	variant := variantByID(t, plan.Definitions[0], "dpkg")
	want := []string{"dpkg", "libc6:amd64", "odd package'$(x);\n:amd64"}
	if !reflect.DeepEqual(variant.Command.Args, want) {
		t.Fatalf("metadata args = %#v, want %#v", variant.Command.Args, want)
	}
	rendered, err := adapter.RenderPOSIX(variant.Command)
	if err != nil || len(rendered) > 64*1024 {
		t.Fatalf("RenderPOSIX = (%d, %v)", len(rendered), err)
	}
}

func TestPackageCollectorGenericPlanIsInert(t *testing.T) {
	collector := Collector{MaxItems: 4096}
	if definitions := collector.Plan(model.HostProfile{}, collect.Discovery{ReferencedPaths: []string{"/bin/sh"}}); len(definitions) != 0 {
		t.Fatalf("generic Plan emitted targeted probes: %#v", definitions)
	}
}

func assertPackageDefinition(t *testing.T, definition probe.Definition, maxCommand int) {
	t.Helper()
	if definition.SafetyClass != model.PassiveRead || definition.Timeout != 10*time.Second || !definition.Idempotent {
		t.Fatalf("unsafe package definition: %#v", definition)
	}
	for _, variant := range definition.Variants {
		rendered, err := adapter.RenderPOSIX(variant.Command)
		if err != nil || len(rendered) > maxCommand {
			t.Fatalf("render %s = %d bytes, err %v, limit %d", variant.ID, len(rendered), err, maxCommand)
		}
	}
}

func variantByID(t *testing.T, definition probe.Definition, id string) probe.Variant {
	t.Helper()
	for _, variant := range definition.Variants {
		if variant.ID == id {
			return variant
		}
	}
	t.Fatalf("variant %q missing from %#v", id, definition)
	return probe.Variant{}
}
