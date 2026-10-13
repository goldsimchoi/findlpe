//go:build integration

package integration

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/normalone/lpeco/internal/vulndb"
)

func TestDebianVersionMatchesDPKGCorpus(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg is unavailable")
	}
	corpus := [][2]string{
		{"1.0", "1.0-0"},
		{"1:1.0", "9.9"},
		{"1.0~rc1", "1.0"},
		{"1.0~~", "1.0~"},
		{"1.0", "1.0a"},
		{"1.0a10", "1.0a2"},
		{"1.001", "1.1"},
		{"1.0a", "1.0+"},
		{"1.0+", "1.0."},
		{"2.35-0ubuntu3.4", "2.35-0ubuntu3.5"},
		{"1.0-1ubuntu1+esm1", "1.0-1ubuntu1"},
		{"1.0-1ubuntu1~22.04.1", "1.0-1ubuntu1"},
		{"1:2:3", "1:2:4"},
		{"1.0-1-2", "1.0-2-1"},
	}
	for _, pair := range corpus {
		for _, ordered := range [][2]string{pair, {pair[1], pair[0]}} {
			got, err := vulndb.CompareDebianVersions(ordered[0], ordered[1])
			if err != nil {
				t.Fatalf("local comparison %q %q: %v", ordered[0], ordered[1], err)
			}
			want, err := dpkgVersionComparison(ordered[0], ordered[1])
			if err != nil {
				t.Fatalf("dpkg comparison %q %q: %v", ordered[0], ordered[1], err)
			}
			if got != want {
				t.Fatalf("comparison %q %q = %d, dpkg = %d", ordered[0], ordered[1], got, want)
			}
		}
	}
}

func dpkgVersionComparison(left, right string) (int, error) {
	for _, candidate := range []struct {
		op   string
		want int
	}{{"lt", -1}, {"eq", 0}, {"gt", 1}} {
		err := exec.Command("dpkg", "--compare-versions", left, candidate.op, right).Run()
		if err == nil {
			return candidate.want, nil
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			return 0, err
		}
	}
	return 0, errors.New("dpkg did not establish an ordering")
}
