package benchmark

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

const ReportSchemaVersion = 1

type Report struct {
	SchemaVersion int          `json:"schema_version"`
	Tools         []ToolReport `json:"tools"`
	Diagnostics   []string     `json:"diagnostics"`
}

type ToolReport struct {
	ToolID         string             `json:"tool_id"`
	ToolName       string             `json:"tool_name"`
	EligibleRuns   int                `json:"eligible_runs"`
	IneligibleRuns int                `json:"ineligible_runs"`
	Rows           []EvaluationRow    `json:"rows"`
	Micro          MetricSet          `json:"micro"`
	Macro          MacroMetrics       `json:"macro"`
	Resources      ResourceMetrics    `json:"resources"`
	Safety         SafetyMetrics      `json:"safety"`
	CrossTransport ConsistencyMetrics `json:"cross_transport"`
	Strata         []StratumReport    `json:"strata"`
	Diagnostics    []string           `json:"diagnostics"`
}

type EvaluationRow struct {
	RunID       string         `json:"run_id"`
	ScenarioID  string         `json:"scenario_id"`
	ToolID      string         `json:"tool_id"`
	Transport   string         `json:"transport"`
	Eligible    bool           `json:"eligible"`
	Expected    ExpectedResult `json:"expected"`
	Outcome     string         `json:"outcome"`
	Observation *Observation   `json:"observation,omitempty"`
	Diagnostics []string       `json:"diagnostics"`
	run         RunIdentity
}

type MetricSet struct {
	Affected ConfusionMetrics `json:"affected"`
	Fixed    ConfusionMetrics `json:"fixed"`
	Path     PathMetrics      `json:"path"`
	Outcomes OutcomeMetrics   `json:"outcomes"`
}

type ConfusionMatrix struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	TN int `json:"tn"`
	FN int `json:"fn"`
}

type ConfusionMetrics struct {
	ConfusionMatrix
	Precision Ratio `json:"precision"`
	Recall    Ratio `json:"recall"`
	F1        Ratio `json:"f1"`
	Accuracy  Ratio `json:"accuracy"`
}

type Ratio struct {
	Numerator   int     `json:"numerator"`
	Denominator int     `json:"denominator"`
	Value       float64 `json:"value"`
	Available   bool    `json:"available"`
}

type PathMetrics struct {
	Exact     Ratio `json:"exact"`
	Adjacent  Ratio `json:"adjacent"`
	P1        Ratio `json:"p1"`
	P2        Ratio `json:"p2"`
	MatchOnly Ratio `json:"match_only"`
	None      Ratio `json:"none"`
}

type OutcomeMetrics struct {
	Complete    Ratio `json:"complete"`
	Unknown     Ratio `json:"unknown"`
	Unsupported Ratio `json:"unsupported"`
	Error       Ratio `json:"error"`
	Timeout     Ratio `json:"timeout"`
	Crash       Ratio `json:"crash"`
	ParseError  Ratio `json:"parse_error"`
	Missing     Ratio `json:"missing"`
	ToolError   Ratio `json:"tool_error"`
}

type MacroMetrics struct {
	AffectedPrecision MacroRatio `json:"affected_precision"`
	AffectedRecall    MacroRatio `json:"affected_recall"`
	AffectedF1        MacroRatio `json:"affected_f1"`
	FixedPrecision    MacroRatio `json:"fixed_precision"`
	FixedRecall       MacroRatio `json:"fixed_recall"`
	FixedF1           MacroRatio `json:"fixed_f1"`
	PathExact         MacroRatio `json:"path_exact"`
	PathAdjacent      MacroRatio `json:"path_adjacent"`
}

type MacroRatio struct {
	Groups    int     `json:"groups"`
	Value     float64 `json:"value"`
	Available bool    `json:"available"`
}

type ResourceMetrics struct {
	ExpectedRuns       int   `json:"expected_runs"`
	ObservedRuns       int   `json:"observed_runs"`
	RuntimeMillisTotal int64 `json:"runtime_millis_total"`
	RuntimeMillisP50   int64 `json:"runtime_millis_p50"`
	RuntimeMillisP95   int64 `json:"runtime_millis_p95"`
	RemoteCommands     int64 `json:"remote_commands"`
	OutputBytesTotal   int64 `json:"output_bytes_total"`
	OutputBytesP50     int64 `json:"output_bytes_p50"`
	OutputBytesP95     int64 `json:"output_bytes_p95"`
	AdapterFailures    int64 `json:"adapter_failures"`
}

type SafetyMetrics struct {
	ExpectedRuns int   `json:"expected_runs"`
	ObservedRuns int   `json:"observed_runs"`
	TargetWrites int64 `json:"target_writes"`
	TargetEgress int64 `json:"target_egress"`
	ZeroWrites   bool  `json:"zero_writes"`
	ZeroEgress   bool  `json:"zero_egress"`
	Passed       bool  `json:"passed"`
}

type ConsistencyMetrics struct {
	ComparedGroups   int   `json:"compared_groups"`
	MismatchedGroups int   `json:"mismatched_groups"`
	Consistent       Ratio `json:"consistent"`
}

type StratumReport struct {
	Dimension string          `json:"dimension"`
	Value     string          `json:"value"`
	Rows      int             `json:"rows"`
	Micro     MetricSet       `json:"micro"`
	Resources ResourceMetrics `json:"resources"`
	Safety    SafetyMetrics   `json:"safety"`
}

func Evaluate(input Manifest, observations []Observation) (Report, error) {
	manifest, err := cloneAndValidateManifest(input)
	if err != nil {
		return Report{}, fmt.Errorf("validate benchmark manifest: %w", err)
	}
	tools := make(map[string]ToolIdentity, len(manifest.Tools))
	for _, tool := range manifest.Tools {
		tools[tool.ID] = tool
	}
	scenarios := make(map[string]Scenario, len(manifest.Scenarios))
	for _, scenario := range manifest.Scenarios {
		scenarios[scenario.ID] = scenario
	}
	runs := make(map[string]RunIdentity, len(manifest.Runs))
	for _, run := range manifest.Runs {
		runs[run.ID] = run
	}
	byRun, err := validateObservations(observations, runs)
	if err != nil {
		return Report{}, err
	}

	rowsByTool := make(map[string][]EvaluationRow, len(tools))
	var reportDiagnostics []string
	for _, run := range manifest.Runs {
		scenario := scenarios[run.ScenarioID]
		observation, found := byRun[run.ID]
		row := EvaluationRow{
			RunID: run.ID, ScenarioID: run.ScenarioID, ToolID: run.ToolID, Transport: run.Transport,
			Eligible: run.Eligible, Expected: scenario.Expected, run: run,
		}
		if found {
			copy := observation
			copy.DiagnosticCodes = canonicalStrings(copy.DiagnosticCodes)
			row.Observation = &copy
			row.Outcome = normalizedOutcome(&copy)
		} else if run.Eligible {
			row.Outcome = "missing"
			row.Diagnostics = []string{"observation is missing"}
		} else {
			row.Outcome = "ineligible"
		}
		if !run.Eligible {
			row.Diagnostics = append(row.Diagnostics, run.Diagnostics...)
			for _, diagnostic := range run.Diagnostics {
				reportDiagnostics = append(reportDiagnostics, fmt.Sprintf("run %s: %s", run.ID, diagnostic))
			}
		}
		row.Diagnostics = canonicalStrings(row.Diagnostics)
		rowsByTool[run.ToolID] = append(rowsByTool[run.ToolID], row)
	}

	toolIDs := make([]string, 0, len(tools))
	for id := range tools {
		toolIDs = append(toolIDs, id)
	}
	sort.Strings(toolIDs)
	report := Report{SchemaVersion: ReportSchemaVersion}
	for _, toolID := range toolIDs {
		rows := rowsByTool[toolID]
		sort.Slice(rows, func(i, j int) bool { return rows[i].RunID < rows[j].RunID })
		toolReport := evaluateTool(tools[toolID], rows)
		if tools[toolID].NotRun && len(rows) == 0 {
			toolReport.Diagnostics = append(toolReport.Diagnostics, "optional baseline tool is explicitly not run")
		}
		toolReport.Diagnostics = canonicalStrings(toolReport.Diagnostics)
		report.Tools = append(report.Tools, toolReport)
	}
	report.Diagnostics = canonicalStrings(reportDiagnostics)
	return report, nil
}

func cloneAndValidateManifest(input Manifest) (Manifest, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return Manifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func validateObservations(values []Observation, runs map[string]RunIdentity) (map[string]Observation, error) {
	byRun := make(map[string]Observation, len(values))
	ids := make(map[string]struct{}, len(values))
	for index, value := range values {
		if value.SchemaVersion != 1 {
			return nil, fmt.Errorf("observation %d has unsupported schema %d", index, value.SchemaVersion)
		}
		if err := validateIdentifier("observation ID", value.ID); err != nil {
			return nil, fmt.Errorf("observation %d: %w", index, err)
		}
		if _, duplicate := ids[value.ID]; duplicate {
			return nil, fmt.Errorf("duplicate observation ID %q", value.ID)
		}
		ids[value.ID] = struct{}{}
		run, exists := runs[value.RunID]
		if !exists {
			return nil, fmt.Errorf("observation %q references unknown run %q", value.ID, value.RunID)
		}
		if _, duplicate := byRun[value.RunID]; duplicate {
			return nil, fmt.Errorf("run %q has duplicate observations", value.RunID)
		}
		if value.ScenarioID != run.ScenarioID || value.ToolID != run.ToolID {
			return nil, fmt.Errorf("observation %q does not match run tool/scenario identity", value.ID)
		}
		if !oneOf(value.Outcome, "complete", "unknown", "unsupported", "error", "timeout", "crash", "parse_error") {
			return nil, fmt.Errorf("observation %q has unsupported outcome %q", value.ID, value.Outcome)
		}
		if value.RuntimeMillis < 0 || value.RemoteCommands < 0 || value.OutputBytes < 0 || value.AdapterFailures < 0 || value.TargetWrites < 0 || value.TargetEgress < 0 {
			return nil, fmt.Errorf("observation %q contains a negative resource or safety counter", value.ID)
		}
		if value.Outcome == "complete" {
			if !oneOf(value.MatchState, "affected", "fixed", "not_affected", "unknown", "none") {
				return nil, fmt.Errorf("observation %q has unsupported match state %q", value.ID, value.MatchState)
			}
			if !oneOf(value.PathTier, "P1", "P2", "match_only", "none") {
				return nil, fmt.Errorf("observation %q has unsupported path tier %q", value.ID, value.PathTier)
			}
		} else {
			if !oneOf(value.MatchState, "", "unknown", "none") || !oneOf(value.PathTier, "", "none") {
				return nil, fmt.Errorf("non-complete observation %q claims a scored state or path", value.ID)
			}
		}
		for label, content := range map[string]string{"package": value.Package, "version": value.Version, "release": value.Release} {
			if err := validateHygieneString(content); err != nil {
				return nil, fmt.Errorf("observation %q %s: %w", value.ID, label, err)
			}
		}
		for _, code := range value.DiagnosticCodes {
			if err := validateIdentifier("diagnostic code", code); err != nil {
				return nil, fmt.Errorf("observation %q: %w", value.ID, err)
			}
		}
		byRun[value.RunID] = value
	}
	return byRun, nil
}

func evaluateTool(tool ToolIdentity, rows []EvaluationRow) ToolReport {
	report := ToolReport{ToolID: tool.ID, ToolName: tool.Name, Rows: rows}
	var eligible []EvaluationRow
	for _, row := range rows {
		if row.Eligible {
			report.EligibleRuns++
			eligible = append(eligible, row)
		} else {
			report.IneligibleRuns++
			for _, diagnostic := range row.Diagnostics {
				report.Diagnostics = append(report.Diagnostics, fmt.Sprintf("run %s: %s", row.RunID, diagnostic))
			}
		}
	}
	report.Micro, report.Resources, report.Safety = aggregateRows(eligible)
	report.Strata = stratifyRows(eligible)
	report.Macro = macroFromStrata(report.Strata)
	report.CrossTransport = transportConsistency(eligible)
	return report
}

func aggregateRows(rows []EvaluationRow) (MetricSet, ResourceMetrics, SafetyMetrics) {
	var metrics MetricSet
	outcomes := make(map[string]int)
	pathCorrect := make(map[string]int)
	pathExpected := make(map[string]int)
	var runtimes, outputSizes []int64
	resources := ResourceMetrics{ExpectedRuns: len(rows)}
	safety := SafetyMetrics{ExpectedRuns: len(rows)}
	exact, adjacent, scoredPaths := 0, 0, 0
	for _, row := range rows {
		outcome := row.Outcome
		if outcome == "" {
			outcome = "missing"
		}
		outcomes[outcome]++
		if row.Observation != nil {
			observation := row.Observation
			resources.ObservedRuns++
			resources.RuntimeMillisTotal += observation.RuntimeMillis
			resources.RemoteCommands += observation.RemoteCommands
			resources.OutputBytesTotal += observation.OutputBytes
			resources.AdapterFailures += observation.AdapterFailures
			runtimes = append(runtimes, observation.RuntimeMillis)
			outputSizes = append(outputSizes, observation.OutputBytes)
			safety.ObservedRuns++
			safety.TargetWrites += observation.TargetWrites
			safety.TargetEgress += observation.TargetEgress
		}
		if outcome != "complete" || row.Observation == nil {
			continue
		}
		observation := row.Observation
		accumulateBinary(&metrics.Affected.ConfusionMatrix, row.Expected.MatchState, observation.MatchState, "affected")
		accumulateBinary(&metrics.Fixed.ConfusionMatrix, row.Expected.MatchState, observation.MatchState, "fixed")
		if row.Expected.MatchState == "unknown" || observation.MatchState == "unknown" {
			continue
		}
		scoredPaths++
		pathExpected[row.Expected.PathTier]++
		if row.Expected.PathTier == observation.PathTier {
			exact++
			pathCorrect[row.Expected.PathTier]++
		}
		if tierDistance(row.Expected.PathTier, observation.PathTier) <= 1 {
			adjacent++
		}
	}
	metrics.Affected = finalizeConfusion(metrics.Affected.ConfusionMatrix)
	metrics.Fixed = finalizeConfusion(metrics.Fixed.ConfusionMatrix)
	metrics.Path = PathMetrics{
		Exact: ratio(exact, scoredPaths), Adjacent: ratio(adjacent, scoredPaths),
		P1: ratio(pathCorrect["P1"], pathExpected["P1"]), P2: ratio(pathCorrect["P2"], pathExpected["P2"]),
		MatchOnly: ratio(pathCorrect["match_only"], pathExpected["match_only"]),
		None:      ratio(pathCorrect["none"], pathExpected["none"]),
	}
	total := len(rows)
	toolErrors := outcomes["error"] + outcomes["timeout"] + outcomes["crash"] + outcomes["parse_error"]
	metrics.Outcomes = OutcomeMetrics{
		Complete: ratio(outcomes["complete"], total), Unknown: ratio(outcomes["unknown"], total),
		Unsupported: ratio(outcomes["unsupported"], total), Error: ratio(outcomes["error"], total),
		Timeout: ratio(outcomes["timeout"], total), Crash: ratio(outcomes["crash"], total),
		ParseError: ratio(outcomes["parse_error"], total), Missing: ratio(outcomes["missing"], total),
		ToolError: ratio(toolErrors, total),
	}
	sort.Slice(runtimes, func(i, j int) bool { return runtimes[i] < runtimes[j] })
	sort.Slice(outputSizes, func(i, j int) bool { return outputSizes[i] < outputSizes[j] })
	resources.RuntimeMillisP50 = percentile(runtimes, 0.50)
	resources.RuntimeMillisP95 = percentile(runtimes, 0.95)
	resources.OutputBytesP50 = percentile(outputSizes, 0.50)
	resources.OutputBytesP95 = percentile(outputSizes, 0.95)
	safety.ZeroWrites = safety.ExpectedRuns > 0 && safety.ObservedRuns == safety.ExpectedRuns && safety.TargetWrites == 0
	safety.ZeroEgress = safety.ExpectedRuns > 0 && safety.ObservedRuns == safety.ExpectedRuns && safety.TargetEgress == 0
	safety.Passed = safety.ZeroWrites && safety.ZeroEgress
	return metrics, resources, safety
}

func accumulateBinary(matrix *ConfusionMatrix, expected, observed, positive string) {
	if expected == "unknown" || observed == "unknown" {
		return
	}
	expectedPositive := expected == positive
	observedPositive := observed == positive
	switch {
	case expectedPositive && observedPositive:
		matrix.TP++
	case !expectedPositive && observedPositive:
		matrix.FP++
	case expectedPositive && !observedPositive:
		matrix.FN++
	default:
		matrix.TN++
	}
}

func finalizeConfusion(matrix ConfusionMatrix) ConfusionMetrics {
	return ConfusionMetrics{
		ConfusionMatrix: matrix,
		Precision:       ratio(matrix.TP, matrix.TP+matrix.FP),
		Recall:          ratio(matrix.TP, matrix.TP+matrix.FN),
		F1:              ratio(2*matrix.TP, 2*matrix.TP+matrix.FP+matrix.FN),
		Accuracy:        ratio(matrix.TP+matrix.TN, matrix.TP+matrix.FP+matrix.TN+matrix.FN),
	}
}

func ratio(numerator, denominator int) Ratio {
	if denominator == 0 {
		return Ratio{}
	}
	return Ratio{Numerator: numerator, Denominator: denominator, Value: float64(numerator) / float64(denominator), Available: true}
}

func percentile(sorted []int64, quantile float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(math.Ceil(quantile*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func tierDistance(first, second string) int {
	ranks := map[string]int{"none": 0, "match_only": 1, "P2": 2, "P1": 3}
	left, leftOK := ranks[first]
	right, rightOK := ranks[second]
	if !leftOK || !rightOK {
		return math.MaxInt
	}
	if left > right {
		return left - right
	}
	return right - left
}

func normalizedOutcome(observation *Observation) string {
	if observation == nil {
		return "missing"
	}
	if observation.Outcome == "complete" && observation.MatchState == "unknown" {
		return "unknown"
	}
	return observation.Outcome
}

func stratifyRows(rows []EvaluationRow) []StratumReport {
	type key struct{ dimension, value string }
	groups := make(map[key][]EvaluationRow)
	for _, row := range rows {
		values := []key{
			{dimension: "release", value: row.run.DistributionID + "/" + row.run.Release},
			{dimension: "package_class", value: row.run.PackageClass},
			{dimension: "scenario_class", value: row.run.ScenarioClass},
			{dimension: "transport", value: row.run.Transport},
		}
		for _, value := range values {
			groups[value] = append(groups[value], row)
		}
	}
	keys := make([]key, 0, len(groups))
	for value := range groups {
		keys = append(keys, value)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].dimension != keys[j].dimension {
			return keys[i].dimension < keys[j].dimension
		}
		return keys[i].value < keys[j].value
	})
	result := make([]StratumReport, 0, len(keys))
	for _, value := range keys {
		micro, resources, safety := aggregateRows(groups[value])
		result = append(result, StratumReport{
			Dimension: value.dimension, Value: value.value, Rows: len(groups[value]),
			Micro: micro, Resources: resources, Safety: safety,
		})
	}
	return result
}

func macroFromStrata(strata []StratumReport) MacroMetrics {
	var result MacroMetrics
	for _, stratum := range strata {
		if stratum.Dimension != "scenario_class" {
			continue
		}
		addMacro(&result.AffectedPrecision, stratum.Micro.Affected.Precision)
		addMacro(&result.AffectedRecall, stratum.Micro.Affected.Recall)
		addMacro(&result.AffectedF1, stratum.Micro.Affected.F1)
		addMacro(&result.FixedPrecision, stratum.Micro.Fixed.Precision)
		addMacro(&result.FixedRecall, stratum.Micro.Fixed.Recall)
		addMacro(&result.FixedF1, stratum.Micro.Fixed.F1)
		addMacro(&result.PathExact, stratum.Micro.Path.Exact)
		addMacro(&result.PathAdjacent, stratum.Micro.Path.Adjacent)
	}
	finalizeMacro(&result.AffectedPrecision)
	finalizeMacro(&result.AffectedRecall)
	finalizeMacro(&result.AffectedF1)
	finalizeMacro(&result.FixedPrecision)
	finalizeMacro(&result.FixedRecall)
	finalizeMacro(&result.FixedF1)
	finalizeMacro(&result.PathExact)
	finalizeMacro(&result.PathAdjacent)
	return result
}

func addMacro(target *MacroRatio, value Ratio) {
	if !value.Available {
		return
	}
	target.Groups++
	target.Value += value.Value
}

func finalizeMacro(target *MacroRatio) {
	if target.Groups == 0 {
		target.Value = 0
		target.Available = false
		return
	}
	target.Value /= float64(target.Groups)
	target.Available = true
}

func transportConsistency(rows []EvaluationRow) ConsistencyMetrics {
	type groupKey struct{ tool, scenario string }
	type semantic struct{ outcome, match, tier string }
	groups := make(map[groupKey]map[string]semantic)
	for _, row := range rows {
		if row.Observation == nil {
			continue
		}
		key := groupKey{tool: row.ToolID, scenario: row.ScenarioID}
		if groups[key] == nil {
			groups[key] = make(map[string]semantic)
		}
		groups[key][row.Transport] = semantic{outcome: row.Outcome, match: row.Observation.MatchState, tier: row.Observation.PathTier}
	}
	var result ConsistencyMetrics
	for _, transports := range groups {
		if len(transports) < 2 {
			continue
		}
		result.ComparedGroups++
		var baseline semantic
		first := true
		mismatch := false
		for _, value := range transports {
			if first {
				baseline, first = value, false
				continue
			}
			if value != baseline {
				mismatch = true
			}
		}
		if mismatch {
			result.MismatchedGroups++
		}
	}
	result.Consistent = ratio(result.ComparedGroups-result.MismatchedGroups, result.ComparedGroups)
	return result
}

func canonicalStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	result := copyValues[:0]
	for _, value := range copyValues {
		if value == "" || (len(result) > 0 && result[len(result)-1] == value) {
			continue
		}
		result = append(result, value)
	}
	return result
}
