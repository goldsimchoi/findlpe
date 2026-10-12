package context

import (
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

const contextScript = `printf 'LPECO_CONTEXT_V1\nSTATUS\n'
cat /proc/self/status 2>/dev/null
printf 'END_STATUS\n'
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
done`

func Definitions() []probe.Definition {
	return []probe.Definition{{
		ID: "context.current", Collector: "context", Parser: "context-v1", RedactionPolicy: "default",
		SafetyClass: model.PassiveRead,
		Variants:    []probe.Variant{{ID: "proc-posix", Command: adapter.Command{Script: contextScript}}},
		Timeout:     10 * time.Second, MaxOutput: 512 * 1024, Produces: []string{"identity", "namespace", "security", "host"}, Idempotent: true,
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
	}
}

var _ collect.Collector = Collector{}
