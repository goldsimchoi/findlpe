package systemdunit

import (
	"reflect"
	"testing"
)

func TestExpandKnownSystemdSpecifiers(t *testing.T) {
	context := SpecifierContext{
		Instance: "blue\\x20team", InstanceUnescaped: "blue team",
		UnitName: "demo@blue\\x20team.service", UnitNameWithoutType: "demo@blue\\x20team",
		Prefix: "demo", UserName: "root", UserID: "0", GroupName: "root", GroupID: "0",
		Home: "/root", RuntimeDir: "/run",
	}
	got, missing := ExpandSpecifiers(`%i|%I|%n|%N|%p|%u|%U|%g|%G|%h|%t|%%`, context)
	want := `blue\x20team|blue team|demo@blue\x20team.service|demo@blue\x20team|demo|root|0|root|0|/root|/run|%`
	if got != want || len(missing) != 0 {
		t.Fatalf("ExpandSpecifiers = %q/%#v, want %q/no missing", got, missing, want)
	}
}

func TestExpandSpecifiersLeavesUnknownAndUnavailableValuesUnresolved(t *testing.T) {
	got, missing := ExpandSpecifiers(`/opt/%i/%Q/%h/%`, SpecifierContext{Instance: "blue"})
	if got != `/opt/blue/%Q/%h/%` {
		t.Fatalf("expanded = %q", got)
	}
	want := []MissingFact{
		{Specifier: "%Q", Reason: "unknown specifier"},
		{Specifier: "%h", Reason: "context unavailable"},
		{Specifier: "%", Reason: "trailing percent"},
	}
	if !reflect.DeepEqual(missing, want) {
		t.Fatalf("missing = %#v, want %#v", missing, want)
	}
}
