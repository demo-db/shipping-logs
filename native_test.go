package shippinglogs_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/dal-go/dalgo/dal"
	"github.com/dal-go/record"
	"github.com/ingitdb/dalgo2ingitdb"
	"github.com/ingitdb/ingitdb-go/ingitdb/validator"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestArchivePreservesOnlyNativeDatabaseFiles(t *testing.T) {
	archiveBytes, err := os.ReadFile("artifacts/shipping-logs.ingitdb.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()

	reader := tar.NewReader(gz)
	var files []string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			files = append(files, header.Name)
			if strings.HasSuffix(header.Name, ".sqlite") || strings.HasSuffix(header.Name, ".db") {
				t.Fatalf("archive contains forbidden parsed snapshot %q", header.Name)
			}
		}
	}
	sort.Strings(files)
	want := []string{
		"ingitdb/.ingitdb/root-collections.yaml",
		"ingitdb/.ingitdb/settings.yaml",
		"ingitdb/collections/baseline/.collection/definition.yaml",
		"ingitdb/collections/baseline/records.jsonl",
		"ingitdb/collections/recovery11045example/.collection/definition.yaml",
		"ingitdb/collections/recovery11045example/records.jsonl",
		"ingitdb/collections/recovery11062example/.collection/definition.yaml",
		"ingitdb/collections/recovery11062example/records.jsonl",
	}
	if strings.Join(files, "\n") != strings.Join(want, "\n") {
		t.Fatalf("archive files differ\ngot: %v\nwant: %v", files, want)
	}
}

func TestSourceManifestPinsLicenseFilesAndEntryRanges(t *testing.T) {
	assertDigest := func(path, want string) []byte {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if got := hex.EncodeToString(digest[:]); got != want {
			t.Fatalf("%s sha256 %s want %s", path, got, want)
		}
		return data
	}

	assertDigest("LICENSE", "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499")
	manifestBytes := assertDigest("source-manifest.json", "fd9c22c47ea5ab589e4e0b00a6bb2b86de6046a678d078684f7feb8422878ab1")
	var source struct {
		Synthetic bool `json:"synthetic"`
		Logs      []struct {
			Path    string `json:"path"`
			Bytes   int    `json:"bytes"`
			SHA256  string `json:"sha256"`
			Entries map[string]struct {
				Artifact    string `json:"artifact"`
				ArtifactSHA string `json:"artifact_sha256"`
				ByteStart   int    `json:"byte_start"`
				ByteEnd     int    `json:"byte_end"`
				EntrySHA    string `json:"entry_sha256"`
			} `json:"entries"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(manifestBytes, &source); err != nil {
		t.Fatal(err)
	}
	if !source.Synthetic || len(source.Logs) != 3 {
		t.Fatalf("unexpected source classification: synthetic=%v logs=%d", source.Synthetic, len(source.Logs))
	}

	collections := map[string]string{
		"base.jsonl":           "baseline",
		"recovery-11045.jsonl": "recovery11045example",
		"recovery-11062.jsonl": "recovery11062example",
	}
	for _, log := range source.Logs {
		collection, ok := collections[filepath.Base(log.Path)]
		if !ok {
			t.Fatalf("unmapped source log %q", log.Path)
		}
		path := filepath.Join("ingitdb", "collections", collection, "records.jsonl")
		data := assertDigest(path, log.SHA256)
		if len(data) != log.Bytes {
			t.Fatalf("%s bytes %d want %d", path, len(data), log.Bytes)
		}
		entries := make([]struct {
			id, artifact, artifactSHA, entrySHA string
			start, end                          int
		}, 0, len(log.Entries))
		for id, entry := range log.Entries {
			entries = append(entries, struct {
				id, artifact, artifactSHA, entrySHA string
				start, end                          int
			}{id, entry.Artifact, entry.ArtifactSHA, entry.EntrySHA, entry.ByteStart, entry.ByteEnd})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].start < entries[j].start })
		cursor := 0
		for _, entry := range entries {
			if entry.artifact != filepath.Base(log.Path) || entry.artifactSHA != log.SHA256 {
				t.Fatalf("%s has inconsistent artifact pin", entry.id)
			}
			if entry.start != cursor || entry.end <= entry.start || entry.end > len(data) {
				t.Fatalf("%s has invalid byte range [%d,%d) after %d", entry.id, entry.start, entry.end, cursor)
			}
			line := data[entry.start:entry.end]
			digest := sha256.Sum256(line)
			if hex.EncodeToString(digest[:]) != entry.entrySHA {
				t.Fatalf("%s entry digest differs", entry.id)
			}
			var row map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(line), &row); err != nil {
				t.Fatalf("%s invalid JSON: %v", entry.id, err)
			}
			if row["event_id"] != entry.id {
				t.Fatalf("entry %s contains event_id %v", entry.id, row["event_id"])
			}
			cursor = entry.end
		}
		if cursor != len(data) {
			t.Fatalf("%s byte ranges cover %d of %d bytes", path, cursor, len(data))
		}
	}
}

func TestOriginalJSONLNativeDALReadQueryAndKeyedReopen(t *testing.T) {
	root := t.TempDir()
	if err := filepath.WalkDir("ingitdb", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(root, path)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, bytes, 0400)
	}); err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Source struct {
			Files map[string]struct {
				Path, SHA256    string
				Bytes, RowCount int
			}
		}
	}
	raw, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	db, err := dalgo2ingitdb.NewDatabase(filepath.Join(root, "ingitdb"), validator.NewCollectionsReader(), dalgo2ingitdb.WithProtectedProfile(), dalgo2ingitdb.WithStoredOnlyReads())
	if err != nil {
		t.Fatal(err)
	}
	for collection, pin := range manifest.Source.Files {
		original, err := os.ReadFile(pin.Path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(original)
		if hex.EncodeToString(digest[:]) != pin.SHA256 || len(original) != pin.Bytes {
			t.Fatal("original file pin changed")
		}
		query := dal.From(dal.NewRootCollectionRef(collection, "")).NewQuery().Limit(100).SelectIntoRecord(func() record.Record {
			return record.NewRecordWithData(record.NewKeyWithID(collection, ""), map[string]any{})
		})
		reader, err := db.ExecuteQueryToRecordsReader(context.Background(), query)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for {
			item, e := reader.Next()
			if e == dal.ErrNoMoreRecords {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			count++
			row := item.Data().(map[string]any)
			id, ok := row["event_id"].(string)
			if !ok || id == "" || item.Key().ID != id {
				t.Fatalf("native key %v %v", item.Key(), row)
			}
			if _, found := row["$ID"]; found {
				t.Fatal("original record rewritten")
			}
			if row["occurred_at"] == nil || row["clock_domain"] == nil || row["precision_ms"] == nil || row["synthetic"] != true {
				t.Fatal("original evidence fields lost")
			}
			reopened := record.NewRecordWithData(record.NewKeyWithID(collection, id), map[string]any{})
			if err := db.Get(context.Background(), reopened); err != nil {
				t.Fatal(err)
			}
			if reopened.Data().(map[string]any)["event_id"] != id {
				t.Fatal("keyed reopen mismatch")
			}
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		if count != pin.RowCount {
			t.Fatalf("%s count%d want%d", collection, count, pin.RowCount)
		}
		after, err := os.ReadFile(filepath.Join(root, pin.Path))
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(original) {
			t.Fatal("DAL changed original source")
		}
	}
}
