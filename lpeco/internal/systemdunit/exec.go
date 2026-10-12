package systemdunit

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type EnvironmentReference struct {
	Name     string `json:"name"`
	Argument int    `json:"argument"`
	Split    bool   `json:"split"`
}

type ExecCommand struct {
	Raw                         string                 `json:"raw"`
	Executable                  string                 `json:"executable"`
	Arguments                   []string               `json:"arguments"`
	SimpleExecutable            bool                   `json:"simple_executable"`
	IgnoreFailure               bool                   `json:"ignore_failure"`
	OverrideArgv0               bool                   `json:"override_argv0"`
	DisableEnvironmentExpansion bool                   `json:"disable_environment_expansion"`
	Shell                       bool                   `json:"shell"`
	PrivilegeMode               string                 `json:"privilege_mode,omitempty"`
	EnvironmentReferences       []EnvironmentReference `json:"environment_references"`
	Valid                       bool                   `json:"valid"`
	Diagnostics                 []Diagnostic           `json:"diagnostics"`
}

func IsExecDirective(name string) bool {
	switch name {
	case "ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost":
		return true
	default:
		return false
	}
}

func ParseExec(value string) ExecCommand {
	command := ExecCommand{Raw: value, Valid: true}
	remainder := strings.TrimSpace(value)
	seenPrefix := make(map[byte]bool)
	for len(remainder) > 0 {
		if strings.HasPrefix(remainder, "!!") {
			if command.PrivilegeMode != "" {
				command.addDiagnostic("conflicting-prefix", "multiple privilege prefixes")
			}
			command.PrivilegeMode = "ambient-fallback"
			remainder = remainder[2:]
			continue
		}
		prefix := remainder[0]
		if !strings.ContainsRune("-:@+!|", rune(prefix)) {
			break
		}
		if seenPrefix[prefix] {
			command.addDiagnostic("duplicate-prefix", fmt.Sprintf("prefix %q is repeated", prefix))
		}
		seenPrefix[prefix] = true
		remainder = remainder[1:]
		switch prefix {
		case '-':
			command.IgnoreFailure = true
		case ':':
			command.DisableEnvironmentExpansion = true
		case '@':
			command.OverrideArgv0 = true
		case '|':
			command.Shell = true
		case '+':
			if command.PrivilegeMode != "" {
				command.addDiagnostic("conflicting-prefix", "'+' and '!' privilege prefixes cannot be combined")
			}
			command.PrivilegeMode = "full"
		case '!':
			if command.PrivilegeMode != "" {
				command.addDiagnostic("conflicting-prefix", "'+' and '!' privilege prefixes cannot be combined")
			}
			command.PrivilegeMode = "ambient"
		}
	}
	tokens, diagnostics := tokenizeExec(remainder)
	command.Diagnostics = append(command.Diagnostics, diagnostics...)
	if len(tokens) == 0 {
		command.addDiagnostic("missing-executable", "Exec command has no executable")
		return command
	}
	command.Executable = tokens[0]
	command.Arguments = append([]string(nil), tokens[1:]...)
	command.SimpleExecutable = !strings.Contains(command.Executable, "/")
	if strings.Contains(command.Executable, "/") && !strings.HasPrefix(command.Executable, "/") {
		command.addDiagnostic("relative-executable", "executable with a slash must be absolute")
	}
	if strings.Contains(command.Executable, "$") {
		command.addDiagnostic("variable-executable", "executable path cannot contain environment expansion")
	}
	if command.OverrideArgv0 && len(command.Arguments) == 0 {
		command.addDiagnostic("missing-argv0", "'@' prefix requires an argv[0] argument")
	}
	if !command.DisableEnvironmentExpansion {
		for index, argument := range command.Arguments {
			command.EnvironmentReferences = append(command.EnvironmentReferences, findEnvironmentReferences(argument, index)...)
		}
	}
	command.Valid = len(command.Diagnostics) == 0
	return command
}

func (c *ExecCommand) addDiagnostic(code, message string) {
	c.Diagnostics = append(c.Diagnostics, Diagnostic{Code: code, Message: message})
	c.Valid = false
}

func tokenizeExec(value string) ([]string, []Diagnostic) {
	var tokens []string
	var current strings.Builder
	var quote rune
	escaped := false
	tokenStarted := false
	runes := []rune(value)
	for index := 0; index < len(runes); index++ {
		character := runes[index]
		if escaped {
			decoded, consumed, ok := decodeEscape(runes[index:])
			if !ok {
				current.WriteRune(character)
			} else {
				current.WriteString(decoded)
				index += consumed - 1
			}
			escaped = false
			tokenStarted = true
			continue
		}
		if character == '\\' {
			escaped = true
			tokenStarted = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				current.WriteRune(character)
			}
			tokenStarted = true
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			tokenStarted = true
			continue
		}
		if unicode.IsSpace(character) {
			if tokenStarted {
				tokens = append(tokens, current.String())
				current.Reset()
				tokenStarted = false
			}
			continue
		}
		current.WriteRune(character)
		tokenStarted = true
	}
	var diagnostics []Diagnostic
	if escaped {
		diagnostics = append(diagnostics, Diagnostic{Code: "trailing-escape", Message: "command ends with a backslash"})
	}
	if quote != 0 {
		diagnostics = append(diagnostics, Diagnostic{Code: "unterminated-quote", Message: "command has an unterminated quote"})
	}
	if tokenStarted {
		tokens = append(tokens, current.String())
	}
	return tokens, diagnostics
}

func decodeEscape(input []rune) (string, int, bool) {
	if len(input) == 0 {
		return "", 0, false
	}
	switch input[0] {
	case 'n':
		return "\n", 1, true
	case 'r':
		return "\r", 1, true
	case 't':
		return "\t", 1, true
	case 's':
		return " ", 1, true
	case '\\', '"', '\'':
		return string(input[0]), 1, true
	case 'x':
		if len(input) >= 3 {
			value, err := strconv.ParseUint(string(input[1:3]), 16, 8)
			if err == nil {
				return string(rune(value)), 3, true
			}
		}
	}
	return string(input[0]), 1, true
}

func findEnvironmentReferences(value string, argument int) []EnvironmentReference {
	var references []EnvironmentReference
	for index := 0; index < len(value); {
		if value[index] != '$' {
			index++
			continue
		}
		if index+1 < len(value) && value[index+1] == '{' {
			end := strings.IndexByte(value[index+2:], '}')
			if end >= 0 {
				name := value[index+2 : index+2+end]
				if validEnvironmentName(name) {
					references = append(references, EnvironmentReference{Name: name, Argument: argument, Split: false})
				}
				index += end + 3
				continue
			}
		}
		end := index + 1
		for end < len(value) && (value[end] == '_' || value[end] >= 'A' && value[end] <= 'Z' || value[end] >= 'a' && value[end] <= 'z' || end > index+1 && value[end] >= '0' && value[end] <= '9') {
			end++
		}
		if end > index+1 {
			references = append(references, EnvironmentReference{Name: value[index+1 : end], Argument: argument, Split: true})
			index = end
			continue
		}
		index++
	}
	return references
}

func validEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}
