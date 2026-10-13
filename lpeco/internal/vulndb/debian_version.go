// Package vulndb stores and compares normalized vendor vulnerability data.
package vulndb

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/normalone/lpeco/internal/model"
)

// ParseDebianVersion parses the Debian Policy
// [epoch:]upstream_version[-debian_revision] syntax. Raw is retained even when
// validation fails so callers can preserve the exact observed target value.
func ParseDebianVersion(raw string) (model.DebianVersion, error) {
	parsed := model.DebianVersion{Raw: raw}
	if raw == "" {
		return parsed, errors.New("version is empty")
	}
	if strings.ContainsRune(raw, '\x00') {
		return parsed, errors.New("version contains NUL")
	}

	remainder := raw
	if separator := strings.IndexByte(raw, ':'); separator >= 0 {
		epochText := raw[:separator]
		if epochText == "" || !allDigits(epochText) {
			return parsed, errors.New("epoch must contain only decimal digits")
		}
		epoch, err := strconv.ParseUint(epochText, 10, 64)
		if err != nil {
			return parsed, fmt.Errorf("parse epoch: %w", err)
		}
		parsed.Epoch = epoch
		remainder = raw[separator+1:]
	}

	upstream := remainder
	revision := ""
	if separator := strings.LastIndexByte(remainder, '-'); separator >= 0 {
		upstream = remainder[:separator]
		revision = remainder[separator+1:]
		if revision == "" {
			return parsed, errors.New("Debian revision is empty")
		}
	}
	if upstream == "" {
		return parsed, errors.New("upstream version is empty")
	}
	if !isASCIIDigit(upstream[0]) {
		return parsed, errors.New("upstream version must start with a decimal digit")
	}
	for index := 0; index < len(upstream); index++ {
		if !validUpstreamByte(upstream[index]) {
			return parsed, fmt.Errorf("upstream version contains invalid byte at offset %d", index)
		}
	}
	for index := 0; index < len(revision); index++ {
		if !validRevisionByte(revision[index]) {
			return parsed, fmt.Errorf("Debian revision contains invalid byte at offset %d", index)
		}
	}

	parsed.Upstream = upstream
	parsed.Revision = revision
	parsed.Valid = true
	return parsed, nil
}

// CompareDebianVersions compares two validated Debian versions using Debian
// Policy ordering and returns only -1, 0, or 1.
func CompareDebianVersions(left, right string) (int, error) {
	leftVersion, err := ParseDebianVersion(left)
	if err != nil {
		return 0, fmt.Errorf("parse left Debian version: %w", err)
	}
	rightVersion, err := ParseDebianVersion(right)
	if err != nil {
		return 0, fmt.Errorf("parse right Debian version: %w", err)
	}
	if leftVersion.Epoch < rightVersion.Epoch {
		return -1, nil
	}
	if leftVersion.Epoch > rightVersion.Epoch {
		return 1, nil
	}
	if result := compareDebianPart(leftVersion.Upstream, rightVersion.Upstream); result != 0 {
		return result, nil
	}
	leftRevision := leftVersion.Revision
	if leftRevision == "" {
		leftRevision = "0"
	}
	rightRevision := rightVersion.Revision
	if rightRevision == "" {
		rightRevision = "0"
	}
	return compareDebianPart(leftRevision, rightRevision), nil
}

func compareDebianPart(left, right string) int {
	leftIndex, rightIndex := 0, 0
	for leftIndex < len(left) || rightIndex < len(right) {
		for hasNonDigit(left, leftIndex) || hasNonDigit(right, rightIndex) {
			leftOrder := debianByteOrder(left, leftIndex)
			rightOrder := debianByteOrder(right, rightIndex)
			if leftOrder < rightOrder {
				return -1
			}
			if leftOrder > rightOrder {
				return 1
			}
			if leftIndex < len(left) {
				leftIndex++
			}
			if rightIndex < len(right) {
				rightIndex++
			}
		}

		for leftIndex < len(left) && left[leftIndex] == '0' {
			leftIndex++
		}
		for rightIndex < len(right) && right[rightIndex] == '0' {
			rightIndex++
		}
		firstDifference := 0
		for leftIndex < len(left) && rightIndex < len(right) && isASCIIDigit(left[leftIndex]) && isASCIIDigit(right[rightIndex]) {
			if firstDifference == 0 {
				firstDifference = int(left[leftIndex]) - int(right[rightIndex])
			}
			leftIndex++
			rightIndex++
		}
		if leftIndex < len(left) && isASCIIDigit(left[leftIndex]) {
			return 1
		}
		if rightIndex < len(right) && isASCIIDigit(right[rightIndex]) {
			return -1
		}
		if firstDifference < 0 {
			return -1
		}
		if firstDifference > 0 {
			return 1
		}
	}
	return 0
}

func hasNonDigit(value string, index int) bool {
	return index < len(value) && !isASCIIDigit(value[index])
}

func debianByteOrder(value string, index int) int {
	if index >= len(value) {
		return 0
	}
	character := value[index]
	if character == '~' {
		return -1
	}
	if isASCIIDigit(character) {
		return 0
	}
	if isASCIILetter(character) {
		return int(character)
	}
	return int(character) + 256
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if !isASCIIDigit(value[index]) {
			return false
		}
	}
	return true
}

func validUpstreamByte(value byte) bool {
	return isASCIIAlphanumeric(value) || strings.ContainsRune(".+-:~", rune(value))
}

func validRevisionByte(value byte) bool {
	return isASCIIAlphanumeric(value) || strings.ContainsRune("+.~", rune(value))
}

func isASCIIAlphanumeric(value byte) bool {
	return isASCIIDigit(value) || isASCIILetter(value)
}

func isASCIIDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
