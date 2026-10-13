package vulndb

import (
	"testing"
)

func TestParseDebianVersion(t *testing.T) {
	tests := []struct {
		raw          string
		wantEpoch    uint64
		wantUpstream string
		wantRevision string
	}{
		{raw: "1.0", wantUpstream: "1.0"},
		{raw: "2:1.0-3ubuntu1", wantEpoch: 2, wantUpstream: "1.0", wantRevision: "3ubuntu1"},
		{raw: "01:2.0~rc1+git-0ubuntu1~22.04.1", wantEpoch: 1, wantUpstream: "2.0~rc1+git", wantRevision: "0ubuntu1~22.04.1"},
		{raw: "1:2:3-4", wantEpoch: 1, wantUpstream: "2:3", wantRevision: "4"},
		{raw: "1.0-1-2", wantUpstream: "1.0-1", wantRevision: "2"},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			got, err := ParseDebianVersion(test.raw)
			if err != nil {
				t.Fatalf("ParseDebianVersion(%q): %v", test.raw, err)
			}
			if got.Raw != test.raw || !got.Valid || got.Epoch != test.wantEpoch || got.Upstream != test.wantUpstream || got.Revision != test.wantRevision {
				t.Fatalf("ParseDebianVersion(%q) = %#v", test.raw, got)
			}
		})
	}
}

func TestParseDebianVersionRejectsInvalidSyntax(t *testing.T) {
	for _, raw := range []string{"", "1.0\x00evil", "1::2", "x:1.0", ":1.0", "abc", "1.0-", "1.0_1", " 1.0", "1.0 "} {
		t.Run(raw, func(t *testing.T) {
			got, err := ParseDebianVersion(raw)
			if err == nil {
				t.Fatalf("ParseDebianVersion(%q) unexpectedly succeeded: %#v", raw, got)
			}
			if got.Raw != raw || got.Valid {
				t.Fatalf("invalid version did not preserve raw input: %#v", got)
			}
		})
	}
}

func TestCompareDebianVersionsPolicyVectors(t *testing.T) {
	tests := []struct {
		name        string
		left, right string
		want        int
	}{
		{name: "epoch wins", left: "1:1.0", right: "9.9", want: 1},
		{name: "missing revision is zero", left: "1.0", right: "1.0-0", want: 0},
		{name: "revision one follows no revision", left: "1.0-1", right: "1.0", want: 1},
		{name: "tilde before end", left: "1.0~rc1", right: "1.0", want: -1},
		{name: "repeated tilde", left: "1.0~~", right: "1.0~", want: -1},
		{name: "end before letter", left: "1.0", right: "1.0a", want: -1},
		{name: "alternating numeric runs", left: "1.0a10", right: "1.0a2", want: 1},
		{name: "leading zero numeric equality", left: "1.001", right: "1.1", want: 0},
		{name: "letters before nonletters", left: "1.0a", right: "1.0+", want: -1},
		{name: "punctuation byte order", left: "1.0+", right: "1.0.", want: -1},
		{name: "ubuntu revision", left: "2.35-0ubuntu3.4", right: "2.35-0ubuntu3.5", want: -1},
		{name: "esm revision", left: "1.0-1ubuntu1+esm1", right: "1.0-1ubuntu1", want: 1},
		{name: "backport sorts before base", left: "1.0-1ubuntu1~22.04.1", right: "1.0-1ubuntu1", want: -1},
		{name: "empty non-digit segment before punctuation", left: "1.0-1", right: "1.0-1+", want: -1},
		{name: "upstream colon after epoch", left: "1:2:3", right: "1:2:4", want: -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := CompareDebianVersions(test.left, test.right)
			if err != nil {
				t.Fatalf("CompareDebianVersions(%q, %q): %v", test.left, test.right, err)
			}
			if got != test.want {
				t.Fatalf("CompareDebianVersions(%q, %q) = %d, want %d", test.left, test.right, got, test.want)
			}
			inverse, err := CompareDebianVersions(test.right, test.left)
			if err != nil || inverse != -test.want {
				t.Fatalf("inverse comparison = %d, %v; want %d", inverse, err, -test.want)
			}
		})
	}
}

func TestCompareDebianVersionsRejectsInvalidInput(t *testing.T) {
	if _, err := CompareDebianVersions("1.0", "1::2"); err == nil {
		t.Fatal("invalid right version was ordered")
	}
	if _, err := CompareDebianVersions("", "1.0"); err == nil {
		t.Fatal("invalid left version was ordered")
	}
}
