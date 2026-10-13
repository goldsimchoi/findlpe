package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/adapter/plugin"
	"github.com/normalone/lpeco/internal/adapter/raw"
	sshtransport "github.com/normalone/lpeco/internal/adapter/ssh"
	"github.com/normalone/lpeco/internal/collect"
	binarycollect "github.com/normalone/lpeco/internal/collect/binary"
	containercollect "github.com/normalone/lpeco/internal/collect/container"
	contextcollect "github.com/normalone/lpeco/internal/collect/context"
	packagecollect "github.com/normalone/lpeco/internal/collect/packageinfo"
	pathcollect "github.com/normalone/lpeco/internal/collect/path"
	processcollect "github.com/normalone/lpeco/internal/collect/process"
	schedulercollect "github.com/normalone/lpeco/internal/collect/scheduler"
	systemdcollect "github.com/normalone/lpeco/internal/collect/systemd"
	"github.com/normalone/lpeco/internal/orchestrator"
	"github.com/normalone/lpeco/internal/redact"
	"github.com/normalone/lpeco/internal/store"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	ExitOK        = 0
	ExitOperation = 1
	ExitUsage     = 2
	ExitPartial   = 3
)

func Execute(ctx context.Context, arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(arguments) == 0 || arguments[0] == "help" || arguments[0] == "--help" || arguments[0] == "-h" {
		_, _ = io.WriteString(stdout, Usage())
		return ExitOK
	}
	configuration, err := Parse(arguments)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "lpeco: %s\n", redact.String(err.Error()))
		return ExitUsage
	}
	switch configuration.Mode {
	case ModeVulnDBSync, ModeVulnDBStatus:
		return executeVulnerabilityDatabase(ctx, configuration, stdout, stderr)
	case ModeReport:
		if err := runReport(ctx, configuration, stdout); err != nil {
			_, _ = fmt.Fprintf(stderr, "lpeco: %s\n", redact.String(err.Error()))
			return ExitOperation
		}
		return ExitOK
	case ModeResume:
		return executeResume(ctx, configuration, stdout, stderr)
	case ModeScanSSH, ModeScanBridge, ModeListenRaw:
		return executeNewScan(ctx, configuration, stdin, stdout, stderr)
	default:
		_, _ = fmt.Fprintln(stderr, "lpeco: unsupported command")
		return ExitUsage
	}
}

func executeNewScan(ctx context.Context, configuration Config, _ io.Reader, stdout, stderr io.Writer) int {
	sessionID := configuration.Common.SessionID
	if sessionID == "" {
		var err error
		sessionID, err = newSessionID()
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "lpeco: cannot create session ID")
			return ExitOperation
		}
	}
	sessionStore, err := store.Open(configuration.Common.StateDir, sessionID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "lpeco: %s\n", redact.String(err.Error()))
		return ExitOperation
	}
	transport, err := buildTransport(ctx, configuration, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "lpeco: %s\n", redact.String(err.Error()))
		return ExitOperation
	}
	options := scanOptions(configuration, sessionID)
	options.Vulnerability = resolveNewVulnerability(ctx, configuration.Vulnerability, time.Now().UTC())
	if configuration.Common.ObservableRead {
		options.BeforeObservable = func(probes []string) error { return showObservablePreview(stderr, probes, true) }
	}
	result, runErr := orchestrator.Run(ctx, transport, sessionStore, options)
	if !configuration.Common.ObservableRead {
		_ = showObservablePreview(stderr, result.ObservablePreview, false)
	}
	if reportErr := writeStoredReport(ctx, sessionStore, sessionID, "terminal", stdout); reportErr != nil {
		_, _ = fmt.Fprintf(stderr, "lpeco: report: %s\n", redact.String(reportErr.Error()))
		if runErr == nil {
			return ExitOperation
		}
	}
	if runErr != nil {
		_, _ = fmt.Fprintf(stderr, "lpeco: scan interrupted; resume session %s (%s)\n", sessionID, redact.String(runErr.Error()))
		return ExitPartial
	}
	return ExitOK
}

func executeResume(ctx context.Context, configuration Config, stdout, stderr io.Writer) int {
	sessionStore, err := store.Open(configuration.Common.StateDir, configuration.ResumeSessionID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "lpeco: %s\n", redact.String(err.Error()))
		return ExitOperation
	}
	session, err := sessionStore.Load(ctx, configuration.ResumeSessionID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "lpeco: %s\n", redact.String(err.Error()))
		return ExitOperation
	}
	transport, err := buildTransport(ctx, configuration, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "lpeco: %s\n", redact.String(err.Error()))
		return ExitOperation
	}
	options := scanOptions(configuration, configuration.ResumeSessionID)
	options.Vulnerability = resolveResumeVulnerability(ctx, configuration.Vulnerability, session, time.Now().UTC())
	if configuration.Common.ObservableRead {
		options.BeforeObservable = func(probes []string) error { return showObservablePreview(stderr, probes, true) }
	}
	result, runErr := orchestrator.Resume(ctx, transport, sessionStore, options)
	if !configuration.Common.ObservableRead {
		_ = showObservablePreview(stderr, result.ObservablePreview, false)
	}
	if reportErr := writeStoredReport(ctx, sessionStore, configuration.ResumeSessionID, "terminal", stdout); reportErr != nil {
		_, _ = fmt.Fprintf(stderr, "lpeco: report: %s\n", redact.String(reportErr.Error()))
		if runErr == nil {
			return ExitOperation
		}
	}
	if runErr != nil {
		_, _ = fmt.Fprintf(stderr, "lpeco: resume remains incomplete (%s)\n", redact.String(runErr.Error()))
		return ExitPartial
	}
	return ExitOK
}

func buildTransport(ctx context.Context, configuration Config, stderr io.Writer) (adapter.Adapter, error) {
	mode := configuration.Mode
	if mode == ModeResume {
		switch configuration.ResumeTransport {
		case "ssh":
			mode = ModeScanSSH
		case "bridge":
			mode = ModeScanBridge
		case "raw":
			mode = ModeListenRaw
		}
	}
	switch mode {
	case ModeScanSSH:
		sshConfiguration := sshtransport.Config{
			Target: configuration.SSH.Target, User: configuration.SSH.User, KeyPath: configuration.SSH.KeyPath,
			KnownHostsPath: configuration.SSH.KnownHostsPath, AgentSocket: configuration.SSH.AgentSocket,
			InsecureIgnoreHostKey: configuration.SSH.InsecureIgnoreHostKey, MaxOutputBytes: configuration.Common.MaxOutput,
		}
		if configuration.SSH.AskPassword {
			sshConfiguration.PasswordCallback = func(context.Context) ([]byte, error) { return readTerminalPassword(stderr) }
		}
		return sshtransport.New(sshConfiguration)
	case ModeScanBridge:
		if configuration.Bridge.Protocol == "jsonrpc" {
			return plugin.Start(ctx, configuration.Bridge.Command, plugin.Options{MaxOutputBytes: configuration.Common.MaxOutput})
		}
		connection, err := raw.StartBridge(ctx, configuration.Bridge.Command)
		if err != nil {
			return nil, err
		}
		return raw.New(connection, raw.Options{TransportKind: "raw-bridge", MaxOutputBytes: configuration.Common.MaxOutput}), nil
	case ModeListenRaw:
		return listenRaw(ctx, configuration, stderr)
	default:
		return nil, errors.New("transport mode is not executable")
	}
}

func scanOptions(configuration Config, sessionID string) orchestrator.Options {
	return orchestrator.Options{
		SessionID: sessionID, TransportKind: transportName(configuration), Target: targetName(configuration),
		Collectors: configuredCollectors(configuration.Common), Full: configuration.Common.Full,
		ObservableRead: configuration.Common.ObservableRead, ProcessObservation: configuration.Common.Observe,
		Vulnerability: orchestrator.VulnerabilityInput{Mode: configuration.Vulnerability.Mode, Explicit: configuration.Vulnerability.SnapshotDir != ""},
	}
}

func configuredCollectors(options CommonOptions) []collect.Collector {
	roots := append([]string(nil), options.ScanRoots...)
	if len(roots) == 0 {
		roots = []string{"/"}
	}
	return []collect.Collector{
		contextcollect.Collector{}, processcollect.Collector{}, systemdcollect.Collector{}, pathcollect.Collector{}, schedulercollect.Collector{},
		binarycollect.Collector{WalkOptions: binarycollect.WalkOptions{Roots: roots, Excludes: append([]string(nil), options.Excludes...), Limit: 10000}},
		packagecollect.Collector{MaxItems: packagecollect.DefaultMaxItems},
		containercollect.Collector{},
	}
}

func transportName(configuration Config) string {
	if configuration.Mode == ModeResume {
		return configuration.ResumeTransport
	}
	switch configuration.Mode {
	case ModeScanSSH:
		return "ssh"
	case ModeScanBridge:
		return configuration.Bridge.Protocol + "-bridge"
	case ModeListenRaw:
		return "raw-listen"
	default:
		return ""
	}
}

func targetName(configuration Config) string {
	if configuration.SSH.Target != "" {
		return configuration.SSH.Target
	}
	if configuration.Raw.Bind != "" {
		return configuration.Raw.Bind
	}
	return "bridge"
}

func readTerminalPassword(destination io.Writer) ([]byte, error) {
	terminalFile, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("interactive password requires a controlling terminal")
	}
	defer terminalFile.Close()
	_, _ = fmt.Fprint(destination, "SSH password: ")
	password, err := terminal.ReadPassword(int(terminalFile.Fd()))
	_, _ = fmt.Fprintln(destination)
	if err != nil {
		return nil, fmt.Errorf("read SSH password: %w", err)
	}
	return password, nil
}

func newSessionID() (string, error) {
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "scan-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random), nil
}

func showObservablePreview(destination io.Writer, probes []string, enabled bool) error {
	if len(probes) == 0 {
		return nil
	}
	if enabled {
		_, err := fmt.Fprintf(destination, "observable-read probes enabled: %s\n", strings.Join(probes, ", "))
		return err
	}
	_, err := fmt.Fprintf(destination, "observable-read probes skipped (rerun with --observable-read): %s\n", strings.Join(probes, ", "))
	return err
}

func Usage() string {
	return `Usage:
  lpeco scan ssh <target> --user <name> [options]
  lpeco listen raw --bind <host:port> [options]
  lpeco scan bridge --adapter '<command>' [--protocol jsonrpc|raw] [options]
  lpeco resume <session-id> --transport ssh|bridge|raw [transport options]
  lpeco report <session-id> --format terminal|json [--state-dir <path>]
  lpeco vuln-db sync [--provider ubuntu] [--db-dir <path>]
  lpeco vuln-db status [--db-dir <path>]

Scans perform read-only collection. Observable reads require --observable-read;
wildcard raw listeners require --allow-public-bind. Scan and resume accept
--vuln-mode auto|off|required and --vuln-db <snapshot-dir>.
`
}
