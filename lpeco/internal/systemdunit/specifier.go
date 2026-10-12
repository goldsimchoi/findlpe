package systemdunit

import "strings"

type SpecifierContext struct {
	Instance            string
	InstanceUnescaped   string
	UnitName            string
	UnitNameWithoutType string
	Prefix              string
	UserName            string
	UserID              string
	GroupName           string
	GroupID             string
	Home                string
	RuntimeDir          string
}

type MissingFact struct {
	Specifier string `json:"specifier"`
	Reason    string `json:"reason"`
}

func ExpandSpecifiers(value string, context SpecifierContext) (string, []MissingFact) {
	values := map[byte]string{
		'i': context.Instance,
		'I': context.InstanceUnescaped,
		'n': context.UnitName,
		'N': context.UnitNameWithoutType,
		'p': context.Prefix,
		'u': context.UserName,
		'U': context.UserID,
		'g': context.GroupName,
		'G': context.GroupID,
		'h': context.Home,
		't': context.RuntimeDir,
		'%': "%",
	}
	var expanded strings.Builder
	var missing []MissingFact
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			expanded.WriteByte(value[index])
			continue
		}
		if index+1 >= len(value) {
			expanded.WriteByte('%')
			missing = append(missing, MissingFact{Specifier: "%", Reason: "trailing percent"})
			continue
		}
		specifier := value[index+1]
		index++
		replacement, known := values[specifier]
		if !known {
			expanded.WriteByte('%')
			expanded.WriteByte(specifier)
			missing = append(missing, MissingFact{Specifier: "%" + string(specifier), Reason: "unknown specifier"})
			continue
		}
		if replacement == "" && specifier != '%' {
			expanded.WriteByte('%')
			expanded.WriteByte(specifier)
			missing = append(missing, MissingFact{Specifier: "%" + string(specifier), Reason: "context unavailable"})
			continue
		}
		expanded.WriteString(replacement)
	}
	return expanded.String(), missing
}
