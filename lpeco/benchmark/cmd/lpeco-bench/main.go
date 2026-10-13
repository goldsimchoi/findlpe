package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/normalone/lpeco/benchmark"
)

const usageText = `usage:
  lpeco-bench validate --manifest PATH
  lpeco-bench import --tool {lpeco|osv-scanner|openscap|manual} --identity PATH --input PATH|- --output PATH [--force]
  lpeco-bench score --manifest PATH --observations PATH [--observations PATH ...] [--output PATH] [--force]
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		writeUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "validate":
		return runValidate(arguments[1:], stdin, stdout, stderr)
	case "import":
		return runImport(arguments[1:], stdin, stdout, stderr)
	case "score":
		return runScore(arguments[1:], stdin, stdout, stderr)
	case "help", "--help", "-h":
		writeUsage(stdout)
		return 0
	default:
		writeUsage(stderr)
		return 2
	}
}

func runValidate(arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet("validate", stderr)
	manifestPath := flags.String("manifest", "", "local manifest path or - for stdin")
	if code, stop := parseFlags(flags, arguments, stderr); stop {
		return code
	}
	if *manifestPath == "" {
		return usageError(stderr, "validate requires --manifest")
	}
	manifest, err := loadManifestPath(*manifestPath, stdin)
	if err != nil {
		return commandError(stderr, "validate", err)
	}
	eligible := 0
	for _, run := range manifest.Runs {
		if run.Eligible {
			eligible++
		}
	}
	result := struct {
		SchemaVersion  int    `json:"schema_version"`
		Status         string `json:"status"`
		Scenarios      int    `json:"scenarios"`
		Runs           int    `json:"runs"`
		EligibleRuns   int    `json:"eligible_runs"`
		IneligibleRuns int    `json:"ineligible_runs"`
	}{1, "valid", len(manifest.Scenarios), len(manifest.Runs), eligible, len(manifest.Runs) - eligible}
	if err := writeCompactJSON(stdout, result); err != nil {
		return commandError(stderr, "validate", err)
	}
	return 0
}

func runImport(arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet("import", stderr)
	tool := flags.String("tool", "", "input format")
	identityPath := flags.String("identity", "", "local run identity path")
	inputPath := flags.String("input", "", "local scanner artifact path or - for stdin")
	outputPath := flags.String("output", "", "local normalized output path")
	force := flags.Bool("force", false, "atomically replace an existing output")
	if code, stop := parseFlags(flags, arguments, stderr); stop {
		return code
	}
	if *tool == "" || *identityPath == "" || *inputPath == "" || *outputPath == "" {
		return usageError(stderr, "import requires --tool, --identity, --input, and --output")
	}
	if *identityPath == "-" {
		return usageError(stderr, "--identity must be a local file")
	}
	if *outputPath == "-" {
		return usageError(stderr, "--output must be a local file")
	}

	identityFile, err := os.Open(*identityPath)
	if err != nil {
		return commandError(stderr, "import", fmt.Errorf("open identity: %w", err))
	}
	runIdentity, loadErr := benchmark.LoadRunIdentity(identityFile)
	closeErr := identityFile.Close()
	if loadErr != nil {
		return commandError(stderr, "import", loadErr)
	}
	if closeErr != nil {
		return commandError(stderr, "import", fmt.Errorf("close identity: %w", closeErr))
	}

	input, closeInput, err := openInput(*inputPath, stdin)
	if err != nil {
		return commandError(stderr, "import", err)
	}
	var observations []benchmark.Observation
	switch *tool {
	case "lpeco":
		observations, err = benchmark.ImportLPECO(input, runIdentity)
	case "osv-scanner":
		observations, err = benchmark.ImportOSVScanner(input, runIdentity)
	case "openscap":
		observations, err = benchmark.ImportOpenSCAP(input, runIdentity)
	case "manual":
		observations, err = benchmark.ImportManual(input, runIdentity)
	default:
		err = fmt.Errorf("unsupported import tool %q", *tool)
	}
	if closeInput != nil {
		if closeErr := closeInput(); err == nil && closeErr != nil {
			err = fmt.Errorf("close input: %w", closeErr)
		}
	}
	if err != nil {
		return commandError(stderr, "import", err)
	}

	var normalized bytes.Buffer
	if err := benchmark.EncodeObservations(&normalized, observations); err != nil {
		return commandError(stderr, "import", err)
	}
	if err := writePrivateAtomic(*outputPath, normalized.Bytes(), *force); err != nil {
		return commandError(stderr, "import", err)
	}
	result := struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		Observations  int    `json:"observations"`
	}{1, "written", len(observations)}
	if err := writeCompactJSON(stdout, result); err != nil {
		return commandError(stderr, "import", err)
	}
	return 0
}

func runScore(arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet("score", stderr)
	manifestPath := flags.String("manifest", "", "local manifest path or - for stdin")
	var observationPaths stringList
	flags.Var(&observationPaths, "observations", "local normalized observation path; repeatable")
	outputPath := flags.String("output", "", "optional local report output path")
	force := flags.Bool("force", false, "atomically replace an existing report output")
	if code, stop := parseFlags(flags, arguments, stderr); stop {
		return code
	}
	if *manifestPath == "" || len(observationPaths) == 0 {
		return usageError(stderr, "score requires --manifest and at least one --observations")
	}
	if *outputPath == "-" {
		return usageError(stderr, "--output must be a local file")
	}
	stdinUses := 0
	if *manifestPath == "-" {
		stdinUses++
	}
	for _, path := range observationPaths {
		if path == "-" {
			stdinUses++
		}
	}
	if stdinUses > 1 {
		return usageError(stderr, "stdin may be selected by only one input")
	}

	manifest, err := loadManifestPath(*manifestPath, stdin)
	if err != nil {
		return commandError(stderr, "score", err)
	}
	for _, runIdentity := range manifest.Runs {
		if !runIdentity.Eligible {
			return commandError(stderr, "score", fmt.Errorf("ineligible run %q: %s", runIdentity.ID, strings.Join(runIdentity.Diagnostics, "; ")))
		}
	}
	var observations []benchmark.Observation
	for _, path := range observationPaths {
		input, closeInput, err := openInput(path, stdin)
		if err != nil {
			return commandError(stderr, "score", err)
		}
		values, loadErr := benchmark.LoadObservations(input)
		if closeInput != nil {
			if closeErr := closeInput(); loadErr == nil && closeErr != nil {
				loadErr = fmt.Errorf("close observations: %w", closeErr)
			}
		}
		if loadErr != nil {
			return commandError(stderr, "score", fmt.Errorf("load observations %q: %w", path, loadErr))
		}
		observations = append(observations, values...)
	}
	report, err := benchmark.Evaluate(manifest, observations)
	if err != nil {
		return commandError(stderr, "score", err)
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return commandError(stderr, "score", fmt.Errorf("encode report: %w", err))
	}
	if *outputPath == "" {
		if _, err := stdout.Write(encoded.Bytes()); err != nil {
			return commandError(stderr, "score", fmt.Errorf("write report: %w", err))
		}
		return 0
	}
	if err := writePrivateAtomic(*outputPath, encoded.Bytes(), *force); err != nil {
		return commandError(stderr, "score", err)
	}
	result := struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		Tools         int    `json:"tools"`
	}{1, "written", len(report.Tools)}
	if err := writeCompactJSON(stdout, result); err != nil {
		return commandError(stderr, "score", err)
	}
	return 0
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	result := flag.NewFlagSet(name, flag.ContinueOnError)
	result.SetOutput(stderr)
	result.Usage = func() { writeUsage(stderr) }
	return result
}

func parseFlags(flags *flag.FlagSet, arguments []string, stderr io.Writer) (int, bool) {
	err := flags.Parse(arguments)
	if errors.Is(err, flag.ErrHelp) {
		return 0, true
	}
	if err != nil {
		return 2, true
	}
	if flags.NArg() != 0 {
		return usageError(stderr, "unexpected positional arguments"), true
	}
	return 0, false
}

func loadManifestPath(path string, stdin io.Reader) (benchmark.Manifest, error) {
	input, closeInput, err := openInput(path, stdin)
	if err != nil {
		return benchmark.Manifest{}, err
	}
	manifest, loadErr := benchmark.LoadManifest(input)
	if closeInput != nil {
		if closeErr := closeInput(); loadErr == nil && closeErr != nil {
			loadErr = fmt.Errorf("close manifest: %w", closeErr)
		}
	}
	return manifest, loadErr
}

func openInput(path string, stdin io.Reader) (io.Reader, func() error, error) {
	if path == "-" {
		if stdin == nil {
			return nil, nil, errors.New("stdin is unavailable")
		}
		return stdin, nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %q: %w", path, err)
	}
	return file, file.Close, nil
}

func writePrivateAtomic(path string, body []byte, force bool) (returnErr error) {
	cleaned := filepath.Clean(path)
	if cleaned == "." || filepath.Base(cleaned) == "." || filepath.Base(cleaned) == string(filepath.Separator) {
		return fmt.Errorf("invalid output path %q", path)
	}
	directory := filepath.Dir(cleaned)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(cleaned)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryPath := temporary.Name()
	temporaryClosed := false
	defer func() {
		if !temporaryClosed {
			if closeErr := temporary.Close(); returnErr == nil && closeErr != nil {
				returnErr = fmt.Errorf("close temporary output: %w", closeErr)
			}
		}
		if removeErr := os.Remove(temporaryPath); returnErr == nil && removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			returnErr = fmt.Errorf("remove temporary output: %w", removeErr)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set private output mode: %w", err)
	}
	if _, err := temporary.Write(body); err != nil {
		return fmt.Errorf("write temporary output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary output: %w", err)
	}
	temporaryClosed = true

	if force {
		if err := os.Rename(temporaryPath, cleaned); err != nil {
			return fmt.Errorf("replace output: %w", err)
		}
	} else {
		if err := os.Link(temporaryPath, cleaned); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("output %q already exists; use --force to replace it", path)
			}
			return fmt.Errorf("publish output: %w", err)
		}
		if err := os.Remove(temporaryPath); err != nil {
			return fmt.Errorf("remove temporary output link: %w", err)
		}
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open output directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	return nil
}

func writeCompactJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write JSON: %w", err)
	}
	return nil
}

func writeUsage(writer io.Writer) {
	_, _ = io.WriteString(writer, usageText)
}

func usageError(stderr io.Writer, message string) int {
	_, _ = fmt.Fprintf(stderr, "lpeco-bench: %s\n", message)
	writeUsage(stderr)
	return 2
}

func commandError(stderr io.Writer, command string, err error) int {
	_, _ = fmt.Fprintf(stderr, "lpeco-bench %s: %v\n", command, err)
	return 1
}

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	if value == "" {
		return errors.New("path must not be empty")
	}
	*values = append(*values, value)
	return nil
}
