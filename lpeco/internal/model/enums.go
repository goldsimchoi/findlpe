package model

type SafetyClass string

const (
	PassiveRead       SafetyClass = "passive-read"
	ObservableRead    SafetyClass = "observable-read"
	TemporaryArtifact SafetyClass = "temporary-artifact"
	StateChanging     SafetyClass = "state-changing"
)

type ProbeStatus string

const (
	ProbeComplete    ProbeStatus = "complete"
	ProbePartial     ProbeStatus = "partial"
	ProbeUnavailable ProbeStatus = "unavailable"
	ProbeTimeout     ProbeStatus = "timeout"
	ProbeTruncated   ProbeStatus = "truncated"
	ProbeParseError  ProbeStatus = "parse_error"
)

type Priority string

const (
	PriorityP0 Priority = "P0"
	PriorityP1 Priority = "P1"
	PriorityP2 Priority = "P2"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type ValidationStatus string

const (
	ValidationUnvalidated ValidationStatus = "unvalidated"
	ValidationReadOnly    ValidationStatus = "read_only_validated"
	ValidationIncomplete  ValidationStatus = "incomplete"
)

type NodeKind string

const (
	NodePrincipal  NodeKind = "Principal"
	NodeProcess    NodeKind = "Process"
	NodeUnit       NodeKind = "Unit"
	NodeTrigger    NodeKind = "Trigger"
	NodeFile       NodeKind = "File"
	NodeDirectory  NodeKind = "Directory"
	NodeExecutable NodeKind = "Executable"
	NodeScript     NodeKind = "Script"
	NodeLibrary    NodeKind = "Library"
	NodeSocket     NodeKind = "Socket"
	NodeMount      NodeKind = "Mount"
	NodeNamespace  NodeKind = "Namespace"
	NodeContainer  NodeKind = "Container"
)

type EdgeKind string

const (
	EdgeRunsAs           EdgeKind = "RUNS_AS"
	EdgeSpawnedBy        EdgeKind = "SPAWNED_BY"
	EdgeManagedBy        EdgeKind = "MANAGED_BY"
	EdgeActivates        EdgeKind = "ACTIVATES"
	EdgeExecutes         EdgeKind = "EXECUTES"
	EdgeInterprets       EdgeKind = "INTERPRETS"
	EdgeLoads            EdgeKind = "LOADS"
	EdgeReadsConfig      EdgeKind = "READS_CONFIG"
	EdgeReadsEnvironment EdgeKind = "READS_ENVIRONMENT"
	EdgeCanWrite         EdgeKind = "CAN_WRITE"
	EdgeCanExecute       EdgeKind = "CAN_EXECUTE"
	EdgeCanTraverse      EdgeKind = "CAN_TRAVERSE"
	EdgeResolvesThrough  EdgeKind = "RESOLVES_THROUGH"
	EdgeLocatedOn        EdgeKind = "LOCATED_ON"
)
