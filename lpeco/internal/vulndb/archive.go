package vulndb

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/ulikunitz/xz"
)

const (
	defaultMaxCompressedBytes int64 = 256 << 20
	defaultMaxEntryBytes      int64 = MaxProviderRecordBytes
	defaultMaxEntries               = 250000
	defaultMaxExpandedBytes   int64 = 4 << 30
)

var errCompressedLimit = errors.New("compressed archive exceeds configured byte limit")

// SyncLimits bounds every untrusted archive dimension used by Sync. Zero
// fields select the production defaults.
type SyncLimits struct {
	MaxCompressedBytes int64
	MaxEntryBytes      int64
	MaxEntries         int
	MaxExpandedBytes   int64
}

type archiveStats struct {
	Entries        int
	RegularEntries int
	ExpandedBytes  int64
}

func iterateXZTar(ctx context.Context, compressed io.Reader, configured SyncLimits, visit func(string, io.Reader) error) (archiveStats, error) {
	var stats archiveStats
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	if compressed == nil || visit == nil {
		return stats, errors.New("archive reader and visitor are required")
	}
	limits, err := resolveSyncLimits(configured)
	if err != nil {
		return stats, err
	}

	bounded := &compressedLimitReader{
		ctx: ctx, reader: compressed, remaining: limits.MaxCompressedBytes,
	}
	decoded, err := (xz.ReaderConfig{SingleStream: true}).NewReader(bounded)
	if err != nil {
		return stats, fmt.Errorf("open XZ stream: %w", err)
	}
	tarReader := tar.NewReader(decoded)
	seen := make(map[string]struct{})

	for {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return stats, fmt.Errorf("read tar header: %w", err)
		}
		stats.Entries++
		if stats.Entries > limits.MaxEntries {
			return stats, fmt.Errorf("archive contains more than %d entries", limits.MaxEntries)
		}
		name, err := validateArchiveName(header.Name, header.Typeflag == tar.TypeDir)
		if err != nil {
			return stats, err
		}
		if _, exists := seen[name]; exists {
			return stats, fmt.Errorf("archive contains duplicate path %q", name)
		}
		seen[name] = struct{}{}

		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				return stats, fmt.Errorf("archive directory %q has non-zero size", name)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > limits.MaxEntryBytes {
				return stats, fmt.Errorf("archive entry %q exceeds %d-byte entry limit", name, limits.MaxEntryBytes)
			}
			if header.Size > limits.MaxExpandedBytes-stats.ExpandedBytes {
				return stats, fmt.Errorf("archive contents exceed %d-byte expanded limit", limits.MaxExpandedBytes)
			}
			stats.RegularEntries++
			stats.ExpandedBytes += header.Size
			entry := &contextReader{ctx: ctx, reader: io.LimitReader(tarReader, header.Size)}
			if err := visit(name, entry); err != nil {
				return stats, fmt.Errorf("process archive entry %q: %w", name, err)
			}
			if _, err := io.Copy(io.Discard, entry); err != nil {
				return stats, fmt.Errorf("finish archive entry %q: %w", name, err)
			}
		default:
			return stats, fmt.Errorf("archive entry %q uses forbidden type %d", name, header.Typeflag)
		}
	}

	// tar.Reader stops after the two zero trailer blocks. Reading the XZ stream
	// to EOF validates its checksum and proves there is neither decompressed
	// data after the tar trailer nor a second/trailing compressed stream.
	trailing, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: decoded}, 1))
	if err != nil {
		return stats, fmt.Errorf("finish XZ stream: %w", err)
	}
	if len(trailing) != 0 {
		return stats, errors.New("archive contains data after the tar trailer")
	}
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	return stats, nil
}

func resolveSyncLimits(limits SyncLimits) (SyncLimits, error) {
	if limits.MaxCompressedBytes < 0 || limits.MaxEntryBytes < 0 || limits.MaxEntries < 0 || limits.MaxExpandedBytes < 0 {
		return SyncLimits{}, errors.New("synchronization limits cannot be negative")
	}
	if limits.MaxCompressedBytes == 0 {
		limits.MaxCompressedBytes = defaultMaxCompressedBytes
	}
	if limits.MaxEntryBytes == 0 {
		limits.MaxEntryBytes = defaultMaxEntryBytes
	}
	if limits.MaxEntries == 0 {
		limits.MaxEntries = defaultMaxEntries
	}
	if limits.MaxExpandedBytes == 0 {
		limits.MaxExpandedBytes = defaultMaxExpandedBytes
	}
	return limits, nil
}

func validateArchiveName(name string, directory bool) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.ContainsRune(name, '\\') || path.IsAbs(name) {
		return "", fmt.Errorf("archive contains unsafe path %q", name)
	}
	candidate := name
	if directory {
		candidate = strings.TrimSuffix(candidate, "/")
	}
	cleaned := path.Clean(candidate)
	if candidate == "" || candidate == "." || candidate == ".." || strings.HasPrefix(candidate, "../") || cleaned != candidate {
		return "", fmt.Errorf("archive contains unsafe path %q", name)
	}
	return cleaned, nil
}

type compressedLimitReader struct {
	ctx       context.Context
	reader    io.Reader
	remaining int64
}

func (reader *compressedLimitReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	if len(buffer) == 0 {
		return 0, nil
	}
	if reader.remaining == 0 {
		var probe [1]byte
		for {
			n, err := reader.reader.Read(probe[:])
			if n > 0 {
				return 0, errCompressedLimit
			}
			if err != nil {
				return 0, err
			}
		}
	}
	if int64(len(buffer)) > reader.remaining {
		buffer = buffer[:reader.remaining]
	}
	n, err := reader.reader.Read(buffer)
	reader.remaining -= int64(n)
	return n, err
}
