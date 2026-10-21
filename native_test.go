package shippinglogs_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dal-go/dalgo/dal"
	"github.com/dal-go/record"
	"github.com/ingitdb/dalgo2ingitdb"
	"github.com/ingitdb/ingitdb-go/ingitdb/validator"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func expectedArchiveMembers() map[string]byte {
	return map[string]byte{
		"ingitdb/.ingitdb/root-collections.yaml":                               tar.TypeReg,
		"ingitdb/.ingitdb/settings.yaml":                                       tar.TypeReg,
		"ingitdb/collections/baseline/.collection/definition.yaml":             tar.TypeReg,
		"ingitdb/collections/baseline/records.jsonl":                           tar.TypeReg,
		"ingitdb/collections/recovery11045example/.collection/definition.yaml": tar.TypeReg,
		"ingitdb/collections/recovery11045example/records.jsonl":               tar.TypeReg,
		"ingitdb/collections/recovery11062example/.collection/definition.yaml": tar.TypeReg,
		"ingitdb/collections/recovery11062example/records.jsonl":               tar.TypeReg,
	}
}

func validateNativeArchive(archiveBytes []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return err
	}
	defer gz.Close()

	reader := tar.NewReader(gz)
	expected := expectedArchiveMembers()
	seen := make(map[string]byte, len(expected))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir {
			return fmt.Errorf("archive member %q has forbidden type %d", header.Name, header.Typeflag)
		}
		clean := path.Clean(header.Name)
		if path.IsAbs(header.Name) || clean != header.Name || clean == "." || strings.HasPrefix(clean, "../") || strings.Contains(header.Name, `\`) {
			return fmt.Errorf("archive member %q has unsafe path", header.Name)
		}
		if clean != "ingitdb" && !strings.HasPrefix(clean, "ingitdb/") {
			return fmt.Errorf("archive member %q escapes ingitdb", header.Name)
		}
		wantType, ok := expected[header.Name]
		if !ok {
			return fmt.Errorf("unexpected archive member %q", header.Name)
		}
		if wantType != header.Typeflag {
			return fmt.Errorf("archive member %q type %d want %d", header.Name, header.Typeflag, wantType)
		}
		if _, duplicate := seen[header.Name]; duplicate {
			return fmt.Errorf("duplicate archive member %q", header.Name)
		}
		seen[header.Name] = header.Typeflag
		if strings.HasSuffix(header.Name, ".sqlite") || strings.HasSuffix(header.Name, ".db") {
			return fmt.Errorf("archive contains forbidden parsed snapshot %q", header.Name)
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			return err
		}
	}
	if len(seen) != len(expected) {
		var missing []string
		for name := range expected {
			if _, ok := seen[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return fmt.Errorf("archive misses members: %v", missing)
	}
	return nil
}

func TestArchivePreservesOnlyNativeDatabaseFiles(t *testing.T) {
	archiveBytes, err := os.ReadFile("artifacts/shipping-logs.ingitdb.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNativeArchive(archiveBytes); err != nil {
		t.Fatal(err)
	}
}

func archiveWithExtraMember(t *testing.T, original []byte, extra tar.Header, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	gzipReader, err := gzip.NewReader(bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatal(err)
		}
		copyHeader := *header
		if err := tarWriter.WriteHeader(&copyHeader); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := gzipReader.Close(); err != nil {
		t.Fatal(err)
	}
	extra.Size = int64(len(body))
	if err := tarWriter.WriteHeader(&extra); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestArchiveRejectsUnsafeAndUnexpectedMembersWithoutChangingSources(t *testing.T) {
	original, err := os.ReadFile("artifacts/shipping-logs.ingitdb.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	sourcePaths := []string{
		"ingitdb/collections/baseline/records.jsonl",
		"ingitdb/collections/recovery11045example/records.jsonl",
		"ingitdb/collections/recovery11062example/records.jsonl",
	}
	sources := make(map[string][]byte, len(sourcePaths))
	for _, sourcePath := range sourcePaths {
		sources[sourcePath], err = os.ReadFile(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
	}

	cases := []tar.Header{
		{Name: "ingitdb/extra.txt", Typeflag: tar.TypeReg, Mode: 0400},
		{Name: "ingitdb/link", Typeflag: tar.TypeSymlink, Linkname: "collections/baseline/records.jsonl", Mode: 0777},
		{Name: "ingitdb/hardlink", Typeflag: tar.TypeLink, Linkname: "ingitdb/collections/baseline/records.jsonl", Mode: 0400},
		{Name: "ingitdb/device", Typeflag: tar.TypeChar, Mode: 0400},
		{Name: "/ingitdb/absolute", Typeflag: tar.TypeReg, Mode: 0400},
		{Name: "ingitdb/../escape", Typeflag: tar.TypeReg, Mode: 0400},
		{Name: "ingitdb/unexpected/", Typeflag: tar.TypeDir, Mode: 0500},
	}
	for _, header := range cases {
		t.Run(strings.ReplaceAll(header.Name, "/", "_"), func(t *testing.T) {
			body := []byte(nil)
			if header.Typeflag == tar.TypeReg {
				body = []byte("unexpected")
			}
			if err := validateNativeArchive(archiveWithExtraMember(t, original, header, body)); err == nil {
				t.Fatalf("unsafe member %q was accepted", header.Name)
			}
		})
	}
	for sourcePath, before := range sources {
		after, err := os.ReadFile(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before) {
			t.Fatalf("archive validation changed original source %s", sourcePath)
		}
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
	var provider struct {
		Source struct {
			IntroducedRevision string `json:"introducedRevision"`
		} `json:"source"`
	}
	providerBytes, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(providerBytes, &provider); err != nil {
		t.Fatal(err)
	}
	if provider.Source.IntroducedRevision != "38a51dda39d988f2d2bcf23703bd1a969d49f4a3" {
		t.Fatalf("unexpected fixture introduction revision %q", provider.Source.IntroducedRevision)
	}
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
