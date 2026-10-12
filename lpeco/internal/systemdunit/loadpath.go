package systemdunit

import (
	"path/filepath"
	"strings"
)

func LoadPathRank(path string) int {
	cleaned := filepath.Clean(path)
	switch {
	case strings.Contains(cleaned, "/etc/systemd/"):
		return 500
	case strings.Contains(cleaned, "/run/systemd/"):
		return 400
	case strings.Contains(cleaned, "/usr/local/lib/systemd/"):
		return 300
	case strings.Contains(cleaned, "/usr/lib/systemd/"):
		return 200
	case strings.Contains(cleaned, "/lib/systemd/"):
		return 100
	default:
		return 0
	}
}

func DropInApplicability(context LoadContext, path string) (bool, int) {
	directory := filepath.Base(filepath.Dir(filepath.Clean(path)))
	if !strings.HasSuffix(directory, ".d") {
		return false, 0
	}
	target := strings.TrimSuffix(directory, ".d")
	suffix := filepath.Ext(context.UnitName)
	if target == strings.TrimPrefix(suffix, ".") {
		return true, 0
	}
	for _, name := range append([]string{context.UnitName}, context.Aliases...) {
		if target == name {
			return true, 3
		}
	}
	if template := templateUnitName(context.UnitName); template != "" && target == template {
		return true, 2
	}
	for _, prefix := range dashedPrefixes(context.UnitName) {
		if target == prefix {
			return true, 1
		}
	}
	return false, 0
}

func templateUnitName(unit string) string {
	at := strings.IndexByte(unit, '@')
	if at < 0 {
		return ""
	}
	dot := strings.LastIndexByte(unit, '.')
	if dot < at {
		return ""
	}
	return unit[:at+1] + unit[dot:]
}

func dashedPrefixes(unit string) []string {
	suffix := filepath.Ext(unit)
	stem := strings.TrimSuffix(unit, suffix)
	var result []string
	for index := strings.IndexByte(stem, '-'); index >= 0; {
		result = append(result, stem[:index+1]+suffix)
		next := strings.IndexByte(stem[index+1:], '-')
		if next < 0 {
			break
		}
		index += next + 1
	}
	return result
}
