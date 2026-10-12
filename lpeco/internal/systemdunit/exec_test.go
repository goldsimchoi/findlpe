package systemdunit

import (
	"reflect"
	"testing"
)

func TestAllServiceExecDirectivesAreRecognized(t *testing.T) {
	for _, name := range []string{"ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost"} {
		if !IsExecDirective(name) {
			t.Fatalf("%s not recognized as an Exec directive", name)
		}
	}
	if IsExecDirective("ExecSearchPath") {
		t.Fatal("ExecSearchPath incorrectly recognized as an Exec command")
	}
}

func TestParseExecUsesSystemdQuotingPrefixesAndLiteralSemicolon(t *testing.T) {
	command := ParseExec(`-:@|/usr/bin/demo argv0 "quoted arg" 'single arg' escaped\ space semi;colon`)
	if !command.Valid || !command.IgnoreFailure || !command.DisableEnvironmentExpansion || !command.OverrideArgv0 || !command.Shell {
		t.Fatalf("prefixes = %#v", command)
	}
	if command.Executable != "/usr/bin/demo" || command.SimpleExecutable {
		t.Fatalf("executable = %#v", command)
	}
	wantArguments := []string{"argv0", "quoted arg", "single arg", "escaped space", "semi;colon"}
	if !reflect.DeepEqual(command.Arguments, wantArguments) {
		t.Fatalf("arguments = %#v, want %#v", command.Arguments, wantArguments)
	}
}

func TestParseExecDistinguishesEnvironmentExpansionModes(t *testing.T) {
	command := ParseExec(`demo --one=${ONE} $WORDS literal`)
	if !command.Valid || !command.SimpleExecutable || command.Executable != "demo" {
		t.Fatalf("command = %#v", command)
	}
	want := []EnvironmentReference{
		{Name: "ONE", Argument: 0, Split: false},
		{Name: "WORDS", Argument: 1, Split: true},
	}
	if !reflect.DeepEqual(command.EnvironmentReferences, want) {
		t.Fatalf("environment references = %#v, want %#v", command.EnvironmentReferences, want)
	}
	disabled := ParseExec(`:demo $WORDS ${ONE}`)
	if len(disabled.EnvironmentReferences) != 0 || !disabled.DisableEnvironmentExpansion {
		t.Fatalf("disabled expansion command = %#v", disabled)
	}
}

func TestParseExecPrivilegePrefixesAndInvalidInputDiagnostics(t *testing.T) {
	tests := []struct {
		input string
		mode  string
	}{
		{input: `+/usr/bin/demo`, mode: "full"},
		{input: `!/usr/bin/demo`, mode: "ambient"},
		{input: `!!/usr/bin/demo`, mode: "ambient-fallback"},
	}
	for _, tt := range tests {
		command := ParseExec(tt.input)
		if !command.Valid || command.PrivilegeMode != tt.mode {
			t.Fatalf("ParseExec(%q) = %#v", tt.input, command)
		}
	}
	conflict := ParseExec(`+!/usr/bin/demo`)
	if conflict.Valid || len(conflict.Diagnostics) == 0 {
		t.Fatalf("conflicting privilege prefixes accepted: %#v", conflict)
	}
	unterminated := ParseExec(`/usr/bin/demo "unterminated`)
	if unterminated.Valid || unterminated.Raw == "" || len(unterminated.Diagnostics) == 0 {
		t.Fatalf("unterminated quote not preserved: %#v", unterminated)
	}
}
