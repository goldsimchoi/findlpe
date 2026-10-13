package redact

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const Redacted = "[REDACTED]"

var (
	urlUserInfoPattern         = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/@\s]+@`)
	authorizationPattern       = regexp.MustCompile(`(?i)(\b(?:proxy-)?authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+`)
	tokenSchemePattern         = regexp.MustCompile(`(?i)\b(bearer|basic)([\t ]+)[^\s,;]+`)
	sensitiveFlagPattern       = regexp.MustCompile(`(?i)(^|[\t ])(--?(?:password|passwd|passphrase|secret|token|api[-_]?key|access[-_]?token|client[-_]?secret|credential|auth|user)(?:=|[\t ]+))([^\s]+)`)
	sensitiveAssignmentPattern = regexp.MustCompile(`(?i)\b([a-z0-9_-]*(?:password|passwd|passphrase|secret|token|api[-_]?key|apikey|credential)[a-z0-9_-]*)\s*=\s*([^&\s;,]+)`)
)

var safeEnvironment = map[string]bool{
	"PATH": true, "LD_LIBRARY_PATH": true, "PYTHONPATH": true, "PERL5LIB": true,
	"RUBYLIB": true, "GEM_PATH": true, "NODE_PATH": true, "CLASSPATH": true,
}

func String(value string) string {
	value = urlUserInfoPattern.ReplaceAllString(value, `${1}`+Redacted+`@`)
	value = authorizationPattern.ReplaceAllString(value, `${1}`+Redacted)
	value = tokenSchemePattern.ReplaceAllString(value, `${1}${2}`+Redacted)
	value = sensitiveFlagPattern.ReplaceAllString(value, `${1}${2}`+Redacted)
	value = sensitiveAssignmentPattern.ReplaceAllString(value, `${1}=`+Redacted)
	return value
}

// TerminalString redacts secrets and makes every untrusted value safe to
// render on one terminal line. Control, formatting, and bidirectional
// override characters are represented explicitly instead of being emitted.
func TerminalString(value string) string {
	value = String(value)
	var output strings.Builder
	for _, character := range value {
		if unicode.IsPrint(character) && !bidirectionalControl(character) {
			output.WriteRune(character)
			continue
		}
		if character <= 0xffff {
			_, _ = fmt.Fprintf(&output, "\\u%04X", character)
		} else {
			_, _ = fmt.Fprintf(&output, "\\U%08X", character)
		}
	}
	return output.String()
}

func bidirectionalControl(character rune) bool {
	return character == '\u061c' || character == '\u200e' || character == '\u200f' ||
		character == '\u2028' || character == '\u2029' || character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}

func Arguments(values []string) []string {
	result := make([]string, len(values))
	maskNext := false
	for index, value := range values {
		if maskNext {
			result[index] = Redacted
			maskNext = false
			continue
		}
		result[index] = String(value)
		if sensitiveFlag(value) && !strings.Contains(value, "=") {
			maskNext = true
		}
	}
	return result
}

func Environment(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		upper := strings.ToUpper(key)
		if isSensitiveKey(upper) || !safeEnvironment[upper] {
			result[key] = Redacted
			continue
		}
		result[key] = String(value)
	}
	return result
}

// JSON redacts a structured fact while preserving its shape, numeric values,
// paths, and evidence identifiers.
func JSON(input json.RawMessage) json.RawMessage {
	if len(input) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(input, &value); err != nil {
		encoded, _ := json.Marshal(String(string(input)))
		return encoded
	}
	encoded, err := json.Marshal(redactValue("", value))
	if err != nil {
		return json.RawMessage(`null`)
	}
	return encoded
}

func redactValue(key string, value any) any {
	switch typed := value.(type) {
	case string:
		if isSensitiveKey(key) {
			return Redacted
		}
		return String(typed)
	case []any:
		if strings.EqualFold(key, "cmdline") || strings.EqualFold(key, "arguments") || strings.EqualFold(key, "argv") {
			arguments := make([]string, len(typed))
			allStrings := true
			for index, item := range typed {
				text, ok := item.(string)
				if !ok {
					allStrings = false
					break
				}
				arguments[index] = text
			}
			if allStrings {
				masked := Arguments(arguments)
				result := make([]any, len(masked))
				for index := range masked {
					result[index] = masked[index]
				}
				return result
			}
		}
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = redactValue(key, item)
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(typed))
		sensitive, _ := typed["sensitive"].(bool)
		keys := make([]string, 0, len(typed))
		for child := range typed {
			keys = append(keys, child)
		}
		sort.Strings(keys)
		for _, child := range keys {
			if sensitive && strings.EqualFold(child, "value") {
				result[child] = Redacted
				continue
			}
			if strings.EqualFold(key, "environment") || strings.EqualFold(key, "env") {
				if text, ok := typed[child].(string); ok {
					result[child] = Environment(map[string]string{child: text})[child]
					continue
				}
			}
			result[child] = redactValue(child, typed[child])
		}
		return result
	default:
		return value
	}
}

func sensitiveFlag(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, flag := range []string{"--password", "--passwd", "--passphrase", "--secret", "--token", "--api-key", "--api_key", "--access-token", "--client-secret", "--credential", "--auth", "--user", "-u"} {
		if value == flag {
			return true
		}
	}
	return false
}

func isSensitiveKey(value string) bool {
	value = strings.ToLower(strings.ReplaceAll(value, "-", "_"))
	for _, fragment := range []string{"password", "passwd", "passphrase", "secret", "token", "api_key", "apikey", "credential", "authorization", "cookie"} {
		if value == fragment || strings.HasSuffix(value, "_"+fragment) || strings.HasPrefix(value, fragment+"_") {
			return true
		}
	}
	return false
}
