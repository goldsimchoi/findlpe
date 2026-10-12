package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/adapter/raw"
	"github.com/normalone/lpeco/internal/store"
)

type Mode string

const (
	ModeScanSSH    Mode = "scan-ssh"
	ModeScanBridge Mode = "scan-bridge"
	ModeListenRaw  Mode = "listen-raw"
	ModeResume     Mode = "resume"
	ModeReport     Mode = "report"
)

type CommonOptions struct {
	StateDir       string
	SessionID      string
	Observe        time.Duration
	Full           bool
	ObservableRead bool
	ScanRoots      []string
	Excludes       []string
	MaxOutput      int
}

type SSHOptions struct {
	Target                string
	User                  string
	KeyPath               string
	KnownHostsPath        string
	AgentSocket           string
	AskPassword           bool
	InsecureIgnoreHostKey bool
}

type RawOptions struct {
	Bind            string
	AllowPublicBind bool
	AcceptTimeout   time.Duration
	Interactive     bool
	TTY             bool
}

type BridgeOptions struct {
	Command  []string
	Protocol string
}

type ReportOptions struct{ Format string }

type Config struct {
	Mode            Mode
	Common          CommonOptions
	SSH             SSHOptions
	Raw             RawOptions
	Bridge          BridgeOptions
	Report          ReportOptions
	ResumeSessionID string
	ResumeTransport string
}

func Parse(arguments []string) (Config, error) {
	if len(arguments) == 0 {
		return Config{}, errors.New("command is required")
	}
	switch arguments[0] {
	case "scan":
		if len(arguments) < 2 {
			return Config{}, errors.New("scan transport is required")
		}
		switch arguments[1] {
		case "ssh":
			return parseScanSSH(arguments[2:])
		case "bridge":
			return parseScanBridge(arguments[2:])
		default:
			return Config{}, fmt.Errorf("unsupported scan transport %q", arguments[1])
		}
	case "listen":
		if len(arguments) < 2 || arguments[1] != "raw" {
			return Config{}, errors.New("listen requires the raw transport")
		}
		return parseListenRaw(arguments[2:])
	case "resume":
		return parseResume(arguments[1:])
	case "report":
		return parseReport(arguments[1:])
	default:
		return Config{}, fmt.Errorf("unknown command %q", arguments[0])
	}
}

func parseScanSSH(arguments []string) (Config, error) {
	if len(arguments) == 0 || strings.HasPrefix(arguments[0], "-") {
		return Config{}, errors.New("SSH target is required before flags")
	}
	configuration := Config{Mode: ModeScanSSH, SSH: SSHOptions{Target: arguments[0]}}
	flags := newFlagSet("scan ssh")
	registerCommon(flags, &configuration.Common)
	registerSSH(flags, &configuration.SSH, false)
	if err := flags.Parse(arguments[1:]); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 || strings.TrimSpace(configuration.SSH.User) == "" {
		return Config{}, errors.New("SSH --user is required and unexpected positional arguments are not allowed")
	}
	if err := validateCommon(&configuration.Common); err != nil {
		return Config{}, err
	}
	return configuration, nil
}

func parseScanBridge(arguments []string) (Config, error) {
	configuration := Config{Mode: ModeScanBridge, Bridge: BridgeOptions{Protocol: "jsonrpc"}}
	flags := newFlagSet("scan bridge")
	registerCommon(flags, &configuration.Common)
	var command string
	flags.StringVar(&command, "adapter", "", "adapter process command")
	flags.StringVar(&configuration.Bridge.Protocol, "protocol", "jsonrpc", "jsonrpc or raw")
	if err := flags.Parse(arguments); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, errors.New("unexpected bridge positional arguments")
	}
	parsed, err := splitCommandLine(command)
	if err != nil {
		return Config{}, err
	}
	configuration.Bridge.Command = parsed
	if err := validateBridge(configuration.Bridge); err != nil {
		return Config{}, err
	}
	if err := validateCommon(&configuration.Common); err != nil {
		return Config{}, err
	}
	return configuration, nil
}

func parseListenRaw(arguments []string) (Config, error) {
	configuration := Config{Mode: ModeListenRaw}
	flags := newFlagSet("listen raw")
	registerCommon(flags, &configuration.Common)
	registerRaw(flags, &configuration.Raw)
	if err := flags.Parse(arguments); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, errors.New("unexpected raw listener positional arguments")
	}
	if err := validateRaw(configuration.Raw); err != nil {
		return Config{}, err
	}
	if err := validateCommon(&configuration.Common); err != nil {
		return Config{}, err
	}
	return configuration, nil
}

func parseResume(arguments []string) (Config, error) {
	if len(arguments) == 0 || strings.HasPrefix(arguments[0], "-") {
		return Config{}, errors.New("resume session ID is required before flags")
	}
	configuration := Config{Mode: ModeResume, ResumeSessionID: arguments[0], Bridge: BridgeOptions{Protocol: "jsonrpc"}}
	flags := newFlagSet("resume")
	registerCommon(flags, &configuration.Common)
	registerSSH(flags, &configuration.SSH, true)
	registerRaw(flags, &configuration.Raw)
	var command string
	flags.StringVar(&configuration.ResumeTransport, "transport", "", "ssh, bridge, or raw")
	flags.StringVar(&command, "adapter", "", "bridge adapter process command")
	flags.StringVar(&configuration.Bridge.Protocol, "protocol", "jsonrpc", "jsonrpc or raw")
	if err := flags.Parse(arguments[1:]); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, errors.New("unexpected resume positional arguments")
	}
	configuration.Common.SessionID = configuration.ResumeSessionID
	parsed, err := splitCommandLineOptional(command)
	if err != nil {
		return Config{}, err
	}
	configuration.Bridge.Command = parsed
	switch configuration.ResumeTransport {
	case "ssh":
		if configuration.SSH.Target == "" || configuration.SSH.User == "" {
			return Config{}, errors.New("SSH resume requires --target and --user")
		}
	case "bridge":
		if err := validateBridge(configuration.Bridge); err != nil {
			return Config{}, err
		}
	case "raw":
		if err := validateRaw(configuration.Raw); err != nil {
			return Config{}, err
		}
	default:
		return Config{}, errors.New("resume --transport must be ssh, bridge, or raw")
	}
	if err := validateCommon(&configuration.Common); err != nil {
		return Config{}, err
	}
	return configuration, nil
}

func parseReport(arguments []string) (Config, error) {
	if len(arguments) == 0 || strings.HasPrefix(arguments[0], "-") {
		return Config{}, errors.New("report session ID is required before flags")
	}
	configuration := Config{Mode: ModeReport, ResumeSessionID: arguments[0], Report: ReportOptions{Format: "terminal"}}
	flags := newFlagSet("report")
	flags.StringVar(&configuration.Common.StateDir, "state-dir", "", "session state directory")
	flags.StringVar(&configuration.Report.Format, "format", "terminal", "terminal or json")
	if err := flags.Parse(arguments[1:]); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, errors.New("unexpected report positional arguments")
	}
	if configuration.Report.Format != "terminal" && configuration.Report.Format != "json" {
		return Config{}, fmt.Errorf("unsupported report format %q", configuration.Report.Format)
	}
	if err := fillStateDir(&configuration.Common); err != nil {
		return Config{}, err
	}
	return configuration, nil
}

func registerCommon(flags *flag.FlagSet, options *CommonOptions) {
	flags.StringVar(&options.StateDir, "state-dir", "", "session state directory")
	flags.StringVar(&options.SessionID, "session-id", "", "explicit new session ID")
	flags.DurationVar(&options.Observe, "observe", 30*time.Second, "process observation duration")
	flags.BoolVar(&options.Full, "full", false, "run fallback collectors even when primary candidates exist")
	flags.BoolVar(&options.ObservableRead, "observable-read", false, "opt in to probes that may be audit-visible")
	flags.Var((*stringList)(&options.ScanRoots), "scan-root", "fallback filesystem root (repeatable)")
	flags.Var((*stringList)(&options.Excludes), "exclude", "fallback filesystem exclusion (repeatable)")
	flags.IntVar(&options.MaxOutput, "max-output", 4*1024*1024, "maximum bytes captured per command")
}

func registerSSH(flags *flag.FlagSet, options *SSHOptions, includeTarget bool) {
	if includeTarget {
		flags.StringVar(&options.Target, "target", "", "SSH host[:port]")
	}
	flags.StringVar(&options.User, "user", "", "SSH user")
	flags.StringVar(&options.KeyPath, "key", "", "SSH private key path")
	flags.StringVar(&options.KnownHostsPath, "known-hosts", "", "known_hosts path")
	flags.StringVar(&options.AgentSocket, "agent", "", "SSH agent socket")
	flags.BoolVar(&options.AskPassword, "ask-password", false, "prompt on a terminal without storing the password")
	flags.BoolVar(&options.InsecureIgnoreHostKey, "insecure-ignore-host-key", false, "disable SSH host-key verification")
}

func registerRaw(flags *flag.FlagSet, options *RawOptions) {
	flags.StringVar(&options.Bind, "bind", "", "listener host:port")
	flags.BoolVar(&options.AllowPublicBind, "allow-public-bind", false, "allow wildcard listener bind")
	flags.DurationVar(&options.AcceptTimeout, "accept-timeout", 5*time.Minute, "listener accept timeout")
	flags.BoolVar(&options.Interactive, "interactive", false, "remote shell is interactive")
	flags.BoolVar(&options.TTY, "tty", false, "remote shell has a TTY")
}

func validateCommon(options *CommonOptions) error {
	if options.Observe < 0 {
		return errors.New("--observe cannot be negative")
	}
	if options.MaxOutput <= 0 {
		return errors.New("--max-output must be positive")
	}
	return fillStateDir(options)
}

func fillStateDir(options *CommonOptions) error {
	if options.StateDir != "" {
		return nil
	}
	value, err := store.DefaultStateDir()
	if err != nil {
		return err
	}
	options.StateDir = value
	return nil
}

func validateRaw(options RawOptions) error {
	if options.AcceptTimeout <= 0 {
		return errors.New("--accept-timeout must be positive")
	}
	host, _, err := net.SplitHostPort(options.Bind)
	if err != nil {
		return fmt.Errorf("parse raw listener bind: %w", err)
	}
	if wildcardHost(host) && !options.AllowPublicBind {
		return raw.ErrPublicBindDenied
	}
	return nil
}

func validateBridge(options BridgeOptions) error {
	if len(options.Command) == 0 {
		return errors.New("--adapter command is required")
	}
	if options.Protocol != "jsonrpc" && options.Protocol != "raw" {
		return fmt.Errorf("unsupported bridge protocol %q", options.Protocol)
	}
	return nil
}

func wildcardHost(host string) bool {
	if host == "" {
		return true
	}
	address := net.ParseIP(strings.Trim(host, "[]"))
	return address != nil && address.IsUnspecified()
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("empty list value")
	}
	*values = append(*values, value)
	return nil
}

func newFlagSet(name string) *flag.FlagSet {
	value := flag.NewFlagSet(name, flag.ContinueOnError)
	value.SetOutput(io.Discard)
	return value
}

func splitCommandLine(value string) ([]string, error) {
	values, err := splitCommandLineOptional(value)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, errors.New("--adapter command is required")
	}
	return values, nil
}

func splitCommandLineOptional(value string) ([]string, error) {
	var result []string
	var current strings.Builder
	var quote rune
	escaped := false
	started := false
	flush := func() {
		if started {
			result = append(result, current.String())
			current.Reset()
			started = false
		}
	}
	for _, character := range value {
		if escaped {
			current.WriteRune(character)
			escaped, started = false, true
			continue
		}
		if character == '\\' {
			escaped, started = true, true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				current.WriteRune(character)
			}
			started = true
			continue
		}
		if character == '\'' || character == '"' {
			quote, started = character, true
			continue
		}
		if character == ' ' || character == '\t' || character == '\n' {
			flush()
			continue
		}
		current.WriteRune(character)
		started = true
	}
	if escaped || quote != 0 {
		return nil, errors.New("unterminated adapter command quote or escape")
	}
	flush()
	return result, nil
}
