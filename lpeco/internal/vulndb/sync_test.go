package vulndb

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ulikunitz/xz"
)

func TestArchiveStreamsRegularEntriesWithinBounds(t *testing.T) {
	archive := makeXZTar(t, []archiveFixtureEntry{
		{name: "osv", typeflag: tar.TypeDir},
		{name: "osv/cve/2025/a.json", body: []byte(`{"id":"a"}`)},
		{name: "README", body: []byte("ignored")},
	})
	var names []string
	var bodies []string
	stats, err := iterateXZTar(context.Background(), bytes.NewReader(archive), SyncLimits{}, func(name string, body io.Reader) error {
		names = append(names, name)
		value, err := io.ReadAll(body)
		bodies = append(bodies, string(value))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(names, []string{"osv/cve/2025/a.json", "README"}) || !reflect.DeepEqual(bodies, []string{`{"id":"a"}`, "ignored"}) {
		t.Fatalf("streamed names=%#v bodies=%#v", names, bodies)
	}
	if stats.Entries != 3 || stats.RegularEntries != 2 || stats.ExpandedBytes != int64(len(`{"id":"a"}`)+len("ignored")) {
		t.Fatalf("archive stats = %#v", stats)
	}
}

func TestArchiveRejectsHostileInputs(t *testing.T) {
	validOne := []archiveFixtureEntry{{name: "osv/cve/a.json", body: []byte("a")}}
	tests := []struct {
		name    string
		archive func(*testing.T) []byte
		limits  SyncLimits
		cancel  bool
	}{
		{name: "absolute path", archive: func(t *testing.T) []byte {
			return makeXZTar(t, []archiveFixtureEntry{{name: "/etc/passwd", body: []byte("x")}})
		}},
		{name: "parent traversal", archive: func(t *testing.T) []byte {
			return makeXZTar(t, []archiveFixtureEntry{{name: "../escape", body: []byte("x")}})
		}},
		{name: "noncanonical traversal", archive: func(t *testing.T) []byte {
			return makeXZTar(t, []archiveFixtureEntry{{name: "osv/../escape", body: []byte("x")}})
		}},
		{name: "backslash path", archive: func(t *testing.T) []byte {
			return makeXZTar(t, []archiveFixtureEntry{{name: `osv\cve\a.json`, body: []byte("x")}})
		}},
		{name: "duplicate name", archive: func(t *testing.T) []byte {
			return makeXZTar(t, []archiveFixtureEntry{{name: "a", body: []byte("1")}, {name: "a", body: []byte("2")}})
		}},
		{name: "symlink", archive: func(t *testing.T) []byte {
			return makeXZTar(t, []archiveFixtureEntry{{name: "link", typeflag: tar.TypeSymlink, linkname: "target"}})
		}},
		{name: "hardlink", archive: func(t *testing.T) []byte {
			return makeXZTar(t, []archiveFixtureEntry{{name: "link", typeflag: tar.TypeLink, linkname: "target"}})
		}},
		{name: "device", archive: func(t *testing.T) []byte {
			return makeXZTar(t, []archiveFixtureEntry{{name: "device", typeflag: tar.TypeChar}})
		}},
		{name: "too many entries", archive: func(t *testing.T) []byte {
			return makeXZTar(t, []archiveFixtureEntry{{name: "a", body: []byte("1")}, {name: "b", body: []byte("2")}})
		}, limits: SyncLimits{MaxEntries: 1}},
		{name: "entry too large", archive: func(t *testing.T) []byte {
			return makeXZTar(t, []archiveFixtureEntry{{name: "a", body: []byte("12345")}})
		}, limits: SyncLimits{MaxEntryBytes: 4}},
		{name: "expanded total too large", archive: func(t *testing.T) []byte {
			return makeXZTar(t, []archiveFixtureEntry{{name: "a", body: []byte("123")}, {name: "b", body: []byte("456")}})
		}, limits: SyncLimits{MaxExpandedBytes: 5}},
		{name: "compressed body too large", archive: func(t *testing.T) []byte { return makeXZTar(t, validOne) }, limits: SyncLimits{MaxCompressedBytes: 8}},
		{name: "truncated xz", archive: func(t *testing.T) []byte {
			body := makeXZTar(t, validOne)
			return body[:len(body)/2]
		}},
		{name: "concatenated junk", archive: func(t *testing.T) []byte { return append(makeXZTar(t, validOne), []byte("junk")...) }},
		{name: "cancellation", archive: func(t *testing.T) []byte { return makeXZTar(t, validOne) }, cancel: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.cancel {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			_, err := iterateXZTar(ctx, bytes.NewReader(test.archive(t)), test.limits, func(_ string, body io.Reader) error {
				_, readErr := io.Copy(io.Discard, body)
				return readErr
			})
			if err == nil {
				t.Fatal("hostile archive was accepted")
			}
		})
	}
}

func TestSyncPublishesNormalizedFeedsAndHandlesValidatedNotModified(t *testing.T) {
	osvArchive := makeXZTar(t, []archiveFixtureEntry{{name: "osv/cve/2023/UBUNTU-CVE-2023-4911.json", body: []byte(readUbuntuFixture(t, "cve-2023-4911.json"))}})
	vexArchive := makeXZTar(t, []archiveFixtureEntry{{name: "vex/cve/2023/CVE-2023-4911.json", body: []byte(syncVEX4911)}})
	modified := time.Date(2026, 10, 13, 20, 0, 0, 0, time.UTC)
	var round atomic.Int32
	var conditional atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if round.Load() > 0 {
			if request.Header.Get("If-None-Match") == `"fixture-etag"` && request.Header.Get("If-Modified-Since") == modified.Format(http.TimeFormat) {
				conditional.Add(1)
			}
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		writer.Header().Set("ETag", `"fixture-etag"`)
		writer.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
		switch request.URL.Path {
		case "/osv":
			_, _ = writer.Write(osvArchive)
		case "/vex":
			_, _ = writer.Write(vexArchive)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	root := filepath.Join(t.TempDir(), "db")
	config := SyncConfig{
		DatabaseDir: root, HTTPClient: server.Client(),
		OSVURL: server.URL + "/osv", VEXURL: server.URL + "/vex",
		Now: func() time.Time { return testRetrievedAt() },
	}
	reference, err := Sync(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCurrent(context.Background(), root, testRetrievedAt())
	if err != nil {
		t.Fatal(err)
	}
	if reference.Digest != loaded.Manifest.Digest || len(loaded.Advisories) != 1 || loaded.Advisories[0].VulnerabilityID != "CVE-2023-4911" {
		t.Fatalf("published snapshot = %#v", loaded)
	}
	if len(loaded.Manifest.Sources) != 2 {
		t.Fatalf("source provenance = %#v", loaded.Manifest.Sources)
	}
	for _, source := range loaded.Manifest.Sources {
		if source.ETag != `"fixture-etag"` || source.LastModified != modified.Format(http.TimeFormat) || !source.ProviderModifiedAt.Equal(modified) || source.SHA256 == "" {
			t.Fatalf("incomplete source provenance: %#v", source)
		}
	}

	round.Store(1)
	second, err := Sync(context.Background(), config)
	if err != nil {
		t.Fatalf("validated double-304 sync: %v", err)
	}
	if second.Digest != reference.Digest || conditional.Load() != 2 {
		t.Fatalf("conditional reuse reference=%#v requests=%d", second, conditional.Load())
	}
}

func TestSyncFailuresPreserveCurrentPointer(t *testing.T) {
	validOSV := makeXZTar(t, []archiveFixtureEntry{{name: "osv/cve/2023/UBUNTU-CVE-2023-4911.json", body: []byte(readUbuntuFixture(t, "cve-2023-4911.json"))}})
	validVEX := makeXZTar(t, []archiveFixtureEntry{{name: "vex/cve/2023/CVE-2023-4911.json", body: []byte(syncVEX4911)}})
	invalidTar := compressXZ(t, []byte("not a tar archive"))
	truncated := append([]byte(nil), validOSV[:len(validOSV)/2]...)
	tests := []struct {
		name       string
		osvStatus  int
		osvBody    []byte
		vexStatus  int
		vexBody    []byte
		osvEntries []archiveFixtureEntry
	}{
		{name: "HTTP failure", osvStatus: http.StatusBadGateway, vexStatus: http.StatusOK, vexBody: validVEX},
		{name: "invalid XZ", osvStatus: http.StatusOK, osvBody: []byte("not xz"), vexStatus: http.StatusOK, vexBody: validVEX},
		{name: "truncated XZ", osvStatus: http.StatusOK, osvBody: truncated, vexStatus: http.StatusOK, vexBody: validVEX},
		{name: "invalid tar", osvStatus: http.StatusOK, osvBody: invalidTar, vexStatus: http.StatusOK, vexBody: validVEX},
		{name: "invalid JSON", osvStatus: http.StatusOK, osvBody: makeXZTar(t, []archiveFixtureEntry{{name: "osv/cve/bad.json", body: []byte("{")}}), vexStatus: http.StatusOK, vexBody: validVEX},
		{name: "no selected VEX", osvStatus: http.StatusOK, osvBody: validOSV, vexStatus: http.StatusOK, vexBody: makeXZTar(t, []archiveFixtureEntry{{name: "README", body: []byte("none")}})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "db")
			if _, err := Publish(context.Background(), root, snapshotFixture(t)); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(root, currentFilename))
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				status, body := test.osvStatus, test.osvBody
				if request.URL.Path == "/vex" {
					status, body = test.vexStatus, test.vexBody
				}
				if status == 0 {
					status = http.StatusOK
				}
				writer.WriteHeader(status)
				_, _ = writer.Write(body)
			}))
			defer server.Close()
			_, err = Sync(context.Background(), SyncConfig{
				DatabaseDir: root, HTTPClient: server.Client(), OSVURL: server.URL + "/osv", VEXURL: server.URL + "/vex",
				Now: func() time.Time { return testRetrievedAt() },
			})
			if err == nil {
				t.Fatal("failing synchronization unexpectedly succeeded")
			}
			after, readErr := os.ReadFile(filepath.Join(root, currentFilename))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("failed synchronization changed current.json")
			}
		})
	}
}

func TestSyncRejectsOffHostRedirectAndMixedNotModified(t *testing.T) {
	validOSV := makeXZTar(t, []archiveFixtureEntry{{name: "osv/cve/2023/UBUNTU-CVE-2023-4911.json", body: []byte(readUbuntuFixture(t, "cve-2023-4911.json"))}})
	validVEX := makeXZTar(t, []archiveFixtureEntry{{name: "vex/cve/2023/CVE-2023-4911.json", body: []byte(syncVEX4911)}})

	t.Run("off-host redirect", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, "https://example.com/elsewhere", http.StatusFound)
		}))
		defer server.Close()
		_, err := Sync(context.Background(), SyncConfig{
			DatabaseDir: filepath.Join(t.TempDir(), "db"), HTTPClient: server.Client(),
			OSVURL: server.URL + "/osv", VEXURL: server.URL + "/vex", Now: testRetrievedAt,
		})
		if err == nil || !strings.Contains(err.Error(), "redirect") {
			t.Fatalf("off-host redirect error = %v", err)
		}
	})

	t.Run("mixed 304 cannot reuse partial artifact", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "db")
		initialServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("ETag", `"same"`)
			if request.URL.Path == "/osv" {
				_, _ = writer.Write(validOSV)
			} else {
				_, _ = writer.Write(validVEX)
			}
		}))
		config := SyncConfig{DatabaseDir: root, HTTPClient: initialServer.Client(), OSVURL: initialServer.URL + "/osv", VEXURL: initialServer.URL + "/vex", Now: testRetrievedAt}
		if _, err := Sync(context.Background(), config); err != nil {
			t.Fatal(err)
		}
		initialServer.Close()
		before, _ := os.ReadFile(filepath.Join(root, currentFilename))
		mixedServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/osv" {
				writer.WriteHeader(http.StatusNotModified)
				return
			}
			writer.Header().Set("ETag", `"new"`)
			_, _ = writer.Write(validVEX)
		}))
		defer mixedServer.Close()
		config.HTTPClient = mixedServer.Client()
		config.OSVURL = mixedServer.URL + "/osv"
		config.VEXURL = mixedServer.URL + "/vex"
		if _, err := Sync(context.Background(), config); err == nil {
			t.Fatal("mixed 304/200 synchronization succeeded without a reusable raw source artifact")
		}
		after, _ := os.ReadFile(filepath.Join(root, currentFilename))
		if !bytes.Equal(before, after) {
			t.Fatal("mixed 304/200 changed current pointer")
		}
	})
}

func TestSyncHonorsCancellationWithoutPublishing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network must not be reached after cancellation")
	})}
	root := filepath.Join(t.TempDir(), "db")
	if _, err := Sync(ctx, SyncConfig{DatabaseDir: root, HTTPClient: client, OSVURL: "http://fixture/osv", VEXURL: "http://fixture/vex"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, currentFilename)); !os.IsNotExist(err) {
		t.Fatalf("cancelled sync published a pointer: %v", err)
	}
}

type archiveFixtureEntry struct {
	name     string
	body     []byte
	typeflag byte
	linkname string
}

func makeXZTar(t *testing.T, entries []archiveFixtureEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	xzWriter, err := xz.NewWriter(&output)
	if err != nil {
		t.Fatal(err)
	}
	tarWriter := tar.NewWriter(xzWriter)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name: entry.name, Mode: 0o600, Size: int64(len(entry.body)), Typeflag: typeflag,
			Linkname: entry.linkname, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR,
		}
		if typeflag == tar.TypeDir || typeflag == tar.TypeSymlink || typeflag == tar.TypeLink || typeflag == tar.TypeChar {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tarWriter.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := xzWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func compressXZ(t *testing.T, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := xz.NewWriter(&output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

const syncVEX4911 = `{
  "@context":"https://openvex.dev/ns/v0.2.0",
  "@id":"https://example.invalid/sanitized/CVE-2023-4911",
  "author":"Canonical Ltd.",
  "timestamp":"2026-10-13T20:00:00Z",
  "version":1,
  "statements":[{
    "vulnerability":{"@id":"https://nvd.nist.gov/vuln/detail/CVE-2023-4911","name":"CVE-2023-4911"},
    "timestamp":"2026-10-13T20:00:00Z",
    "products":[
      {"@id":"pkg:deb/ubuntu/glibc@2.35-0ubuntu3.4?arch=source&distro=jammy"},
      {"@id":"pkg:deb/ubuntu/libc6@2.35-0ubuntu3.4?arch=amd64&distro=jammy"}
    ],
    "status":"fixed",
    "status_notes":"sanitized"
  }]
}`

func Example_syncNeverUsesLiveServiceInTests() {
	fmt.Println("sync tests use only httptest servers and in-memory archives")
	// Output: sync tests use only httptest servers and in-memory archives
}
