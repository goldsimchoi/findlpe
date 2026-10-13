package vulndb

import "testing"

func FuzzCompareDebianVersions(f *testing.F) {
	for _, seed := range [][2]string{
		{"1.0", "1.0-0"},
		{"1:1.0", "9.9"},
		{"2.35-0ubuntu3.4", "2.35-0ubuntu3.5"},
		{"1.0~rc1", "1.0"},
		{"1.001", "1.1"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, left, right string) {
		leftParsed, leftErr := ParseDebianVersion(left)
		rightParsed, rightErr := ParseDebianVersion(right)
		if leftErr != nil || rightErr != nil || !leftParsed.Valid || !rightParsed.Valid {
			return
		}
		forward, err := CompareDebianVersions(left, right)
		if err != nil {
			t.Fatalf("valid versions failed comparison: %v", err)
		}
		if forward < -1 || forward > 1 {
			t.Fatalf("comparison returned %d", forward)
		}
		reverse, err := CompareDebianVersions(right, left)
		if err != nil || reverse != -forward {
			t.Fatalf("antisymmetry failed: forward=%d reverse=%d err=%v", forward, reverse, err)
		}
		self, err := CompareDebianVersions(left, left)
		if err != nil || self != 0 {
			t.Fatalf("reflexivity failed: self=%d err=%v", self, err)
		}
	})
}
