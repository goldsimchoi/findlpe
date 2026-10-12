package redact

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestStringMasksSecretsWithoutDestroyingPathsOrEvidenceIDs(t *testing.T) {
	tests := []struct{ input, want string }{
		{"https://alice:hunter2@example.test/api", "https://[REDACTED]@example.test/api"},
		{"TOKEN=abc123", "TOKEN=[REDACTED]"},
		{"Authorization: Bearer abc.def.ghi", "Authorization: Bearer [REDACTED]"},
		{"proxy-authorization: Basic dXNlcjpwYXNz", "proxy-authorization: Basic [REDACTED]"},
		{"tool --password hunter2 --output /tmp/result", "tool --password [REDACTED] --output /tmp/result"},
		{"tool --api-key=abc123 /etc/secret.conf evidence-secret-id", "tool --api-key=[REDACTED] /etc/secret.conf evidence-secret-id"},
		{"/opt/app/token-helper evidence-012345", "/opt/app/token-helper evidence-012345"},
	}
	for _, test := range tests {
		if got := String(test.input); got != test.want {
			t.Errorf("String(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestArgumentsAndEnvironmentApplyContextAwareMasking(t *testing.T) {
	arguments := []string{"curl", "--user", "alice:hunter2", "--header", "Authorization: Bearer token", "/tmp/secret-file"}
	wantArguments := []string{"curl", "--user", Redacted, "--header", "Authorization: Bearer [REDACTED]", "/tmp/secret-file"}
	if got := Arguments(arguments); !reflect.DeepEqual(got, wantArguments) {
		t.Fatalf("Arguments = %#v, want %#v", got, wantArguments)
	}
	environment := map[string]string{"PATH": "/usr/local/bin:/usr/bin", "LD_LIBRARY_PATH": "/opt/demo/lib", "API_TOKEN": "token", "CUSTOM": "private"}
	wantEnvironment := map[string]string{"PATH": "/usr/local/bin:/usr/bin", "LD_LIBRARY_PATH": "/opt/demo/lib", "API_TOKEN": Redacted, "CUSTOM": Redacted}
	if got := Environment(environment); !reflect.DeepEqual(got, wantEnvironment) {
		t.Fatalf("Environment = %#v, want %#v", got, wantEnvironment)
	}
}

func TestJSONMasksValuesMarkedSensitive(t *testing.T) {
	input := json.RawMessage(`{"pid":42,"values":{"PATH":{"value":"/private/toolchain/bin","sensitive":true},"DISPLAY":{"value":":0","sensitive":false}}}`)
	output := JSON(input)
	if strings.Contains(string(output), "/private/toolchain/bin") {
		t.Fatalf("JSON leaked sensitive environment value: %s", output)
	}
	var decoded struct {
		Values map[string]struct {
			Value     string `json:"value"`
			Sensitive bool   `json:"sensitive"`
		} `json:"values"`
	}
	if err := json.Unmarshal(output, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Values["PATH"].Value != Redacted || !decoded.Values["PATH"].Sensitive {
		t.Fatalf("sensitive value = %#v", decoded.Values["PATH"])
	}
	if decoded.Values["DISPLAY"].Value != ":0" || decoded.Values["DISPLAY"].Sensitive {
		t.Fatalf("non-sensitive value = %#v", decoded.Values["DISPLAY"])
	}
}

func FuzzRedact(f *testing.F) {
	for _, seed := range []string{"TOKEN=secret", "https://u:p@example.test/x", "--password value", "/etc/secret.conf", "Bearer abc"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		output := String(input)
		if again := String(output); again != output {
			t.Fatalf("redaction is not idempotent: %q -> %q", output, again)
		}
	})
}
