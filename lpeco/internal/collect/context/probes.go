package context

import (
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

const contextScript = `printf 'LPECO_CONTEXT_V2\nSTATUS\n'
cat /proc/self/status 2>/dev/null
printf 'END_STATUS\n'
_lpeco_hex_text() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
_lpeco_hex_file() { od -An -v -tx1 -- "$1" 2>/dev/null | tr -d ' \n'; }
for _lpeco_ns in user pid mnt net ipc uts cgroup; do
  _lpeco_value=$(readlink "/proc/self/ns/$_lpeco_ns" 2>/dev/null) || continue
  printf 'NS\t%s\t%s\n' "$_lpeco_ns" "$_lpeco_value"
done
if [ -r /proc/self/attr/current ]; then
  _lpeco_lsm=$(cat /proc/self/attr/current 2>/dev/null)
  printf 'LSM\tcurrent\t%s\n' "$_lpeco_lsm"
fi
printf 'OS\t%s\n' "$(uname -s 2>/dev/null)"
printf 'ARCH\t%s\n' "$(uname -m 2>/dev/null)"
_lpeco_init=$(cat /proc/1/comm 2>/dev/null)
printf 'INIT\t%s\n' "$_lpeco_init"
if [ "$_lpeco_init" = systemd ] && [ -d /run/systemd/system ]; then printf 'SYSTEMD_RUNNING\t1\n'; else printf 'SYSTEMD_RUNNING\t0\n'; fi
for _lpeco_cmd in systemctl stat readlink getfacl getcap readelf objdump sudo find dpkg-query rpm apk; do
  if command -v "$_lpeco_cmd" >/dev/null 2>&1; then printf 'COMMAND\t%s\t1\n' "$_lpeco_cmd"; else printf 'COMMAND\t%s\t0\n' "$_lpeco_cmd"; fi
done
_lpeco_os_release=
if [ -e /etc/os-release ] || [ -L /etc/os-release ]; then
  _lpeco_os_release=/etc/os-release
elif [ -e /usr/lib/os-release ] || [ -L /usr/lib/os-release ]; then
  _lpeco_os_release=/usr/lib/os-release
fi
if [ -z "$_lpeco_os_release" ]; then
  printf 'OS_RELEASE\tabsent\t\t\n'
elif [ -r "$_lpeco_os_release" ]; then
  printf 'OS_RELEASE\treadable\t%s\t%s\n' "$(_lpeco_hex_text "$_lpeco_os_release")" "$(_lpeco_hex_file "$_lpeco_os_release")"
else
  printf 'OS_RELEASE\tunreadable\t%s\t\n' "$(_lpeco_hex_text "$_lpeco_os_release")"
fi
_lpeco_kernel_release=$(uname -r 2>/dev/null) || _lpeco_kernel_release=
_lpeco_kernel_version=$(uname -v 2>/dev/null) || _lpeco_kernel_version=
printf 'KERNEL\t%s\t%s\n' "$(_lpeco_hex_text "$_lpeco_kernel_release")" "$(_lpeco_hex_text "$_lpeco_kernel_version")"`

func Definitions() []probe.Definition {
	return []probe.Definition{{
		ID: "context.current", Collector: "context", Parser: "context-v2", RedactionPolicy: "default",
		SafetyClass: model.PassiveRead,
		Variants:    []probe.Variant{{ID: "proc-posix", Command: adapter.Command{Script: contextScript}}},
		Timeout:     10 * time.Second, MaxOutput: 512 * 1024,
		Produces: []string{"identity", "namespace", "security", "host", "distribution", "kernel"}, Idempotent: true,
	}}
}

type Collector struct{}

func (Collector) ID() string { return "context" }

func (Collector) Plan(model.HostProfile, collect.Discovery) []probe.Definition { return Definitions() }

func (Collector) Parse(_ probe.Definition, result adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
	parsed, err := ParseOutput(result.Stdout)
	if err != nil {
		return nil, err
	}
	if result.Status != "" && result.Status != model.ProbeComplete {
		missing := "context observation is " + string(result.Status)
		parsed.Distribution.MissingFacts = uniqueSortedStrings(append(parsed.Distribution.MissingFacts, missing))
		parsed.Distribution.Confidence = model.ConfidenceMedium
		parsed.Kernel.MissingFacts = uniqueSortedStrings(append(parsed.Kernel.MissingFacts, missing))
		parsed.Kernel.Confidence = model.ConfidenceMedium
	}
	return Facts(parsed, evidenceID)
}

func HostProfile(parsed ParsedContext) model.HostProfile {
	namespaces := make(map[string]string, len(parsed.Namespaces.IDs))
	for key, value := range parsed.Namespaces.IDs {
		namespaces[key] = value
	}
	commands := make(map[string]bool, len(parsed.Host.AvailableCommands))
	for key, value := range parsed.Host.AvailableCommands {
		commands[key] = value
	}
	return model.HostProfile{
		OS: parsed.Host.OS, Architecture: parsed.Host.Architecture, InitSystem: parsed.Host.InitSystem,
		SystemdRunning: parsed.Host.SystemdRunning, AvailableCommands: commands, NamespaceIDs: namespaces,
		MissingCapabilities: append([]string(nil), parsed.MissingFacts...),
		Distribution:        cloneDistribution(parsed.Distribution), Kernel: cloneKernel(parsed.Kernel),
	}
}

func cloneDistribution(value model.DistributionProfile) model.DistributionProfile {
	value.IDLike = append([]string(nil), value.IDLike...)
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	value.MissingFacts = append([]string(nil), value.MissingFacts...)
	return value
}

func cloneKernel(value model.KernelProfile) model.KernelProfile {
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	value.MissingFacts = append([]string(nil), value.MissingFacts...)
	return value
}

var _ collect.Collector = Collector{}
