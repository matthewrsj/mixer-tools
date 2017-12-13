package swupd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestReadManifestHeaderManifest(t *testing.T) {
	m := Manifest{}
	if err := readManifestFileHeaderLine([]string{"MANIFEST", "2"}, &m); err != nil {
		t.Error("failed to read MANIFEST header")
	}

	if m.Header.Format != 2 {
		t.Errorf("manifest Format header set to %d when 2 was expected", m.Header.Format)
	}
}

func TestReadManifestHeaderManifestBad(t *testing.T) {
	m := Manifest{}
	if err := readManifestFileHeaderLine([]string{"MANIFEST", "i"}, &m); err == nil {
		t.Error("readManifestFileHeaderLine did not fail with invalid format header")
	}

	if m.Header.Format != 0 {
		t.Errorf("manifest Format header set to %d on invalid format", m.Header.Format)
	}
}

func TestReadManifestHeaderVersion(t *testing.T) {
	m := Manifest{}
	if err := readManifestFileHeaderLine([]string{"version:", "10"}, &m); err != nil {
		t.Error("failed to read version header")
	}

	if m.Header.Version != 10 {
		t.Errorf("manifest Version header set to %d when 20 was expected", m.Header.Version)
	}
}

func TestReadManifestHeaderVersionBad(t *testing.T) {
	m := Manifest{}
	if err := readManifestFileHeaderLine([]string{"version:", " "}, &m); err == nil {
		t.Error("readManifestFileHeaderLine did not fail with invalid version header")
	}

	if m.Header.Version != 0 {
		t.Errorf("manifest Version header set to %d on invalid version", m.Header.Version)
	}
}

func TestReadManifestHeaderFilecount(t *testing.T) {
	m := Manifest{}
	if err := readManifestFileHeaderLine([]string{"filecount:", "1000"}, &m); err != nil {
		t.Error("failed to read filecount header")
	}

	if m.Header.FileCount != 1000 {
		t.Errorf("manifest FileCount header set to %d when 1000 was expected", m.Header.FileCount)
	}
}

func TestReadManifestHeaderFilecountBad(t *testing.T) {
	m := Manifest{}
	if err := readManifestFileHeaderLine([]string{"filecount:", "i"}, &m); err == nil {
		t.Error("readManifestFileHeaderLine did not fail with invalid filecount header")
	}

	if m.Header.FileCount != 0 {
		t.Errorf("manifest FileCount header set to %d on invalid filecount", m.Header.FileCount)
	}
}

func TestReadManifestHeaderTimestamp(t *testing.T) {
	m := Manifest{}
	if err := readManifestFileHeaderLine([]string{"timestamp:", "1000"}, &m); err != nil {
		t.Error("failed to read timestamp header")
	}

	if m.Header.TimeStamp != time.Unix(1000, 0) {
		t.Errorf("manifest TimeStamp header set to %v when 1000 was expected", m.Header.TimeStamp)
	}
}

func TestReadManifestHeaderTimestampBad(t *testing.T) {
	m := Manifest{}
	if err := readManifestFileHeaderLine([]string{"timestamp:", "i"}, &m); err == nil {
		t.Error("readManifestFileHeaderLine did not fail with invalid timestamp header")
	}

	if !m.Header.TimeStamp.IsZero() {
		t.Errorf("manifest TimeStamp header set to %v on invalid timestamp", m.Header.TimeStamp)
	}
}

func TestReadManifestHeaderContentsize(t *testing.T) {
	m := Manifest{}
	if err := readManifestFileHeaderLine([]string{"contentsize:", "1000"}, &m); err != nil {
		t.Error("failed to read contentsize header")
	}

	if m.Header.ContentSize != 1000 {
		t.Errorf("manifest ContentSize header set to %d when 1000 was expected", m.Header.ContentSize)
	}
}

func TestReadManifestHeaderContentsizeBad(t *testing.T) {
	m := Manifest{}
	if err := readManifestFileHeaderLine([]string{"contentsize:", "i"}, &m); err == nil {
		t.Error("readManifestFileHeaderLine did not fail with invalid contentsize header")
	}

	if m.Header.ContentSize != 0 {
		t.Errorf("manifest ContentSize header set to %d on invalid contentsize", m.Header.ContentSize)
	}
}

func TestReadManifestHeaderIncludes(t *testing.T) {
	m := Manifest{}
	if err := readManifestFileHeaderLine([]string{"includes:", "test-bundle"}, &m); err != nil {
		t.Error("failed to read includes header")
	}

	var expected []*Manifest
	expected = append(expected, &Manifest{Name: "test-bundle"})
	if !reflect.DeepEqual(m.Header.Includes, expected) {
		t.Errorf("manifest Includes set to %v when %v expected", m.Header.Includes, expected)
	}

	if err := readManifestFileHeaderLine([]string{"includes:", "test-bundle2"}, &m); err != nil {
		t.Error("failed to read second includes header")
	}

	expected = append(expected, &Manifest{Name: "test-bundle2"})
	if !reflect.DeepEqual(m.Header.Includes, expected) {
		t.Errorf("manifest Includes set to %v when %v expected", m.Header.Includes, expected)
	}
}

func TestReadManifestFileEntry(t *testing.T) {
	validHash := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	validManifestLines := [][]string{
		{"Fdbr", validHash, "10", "/usr/testfile"},
		{"FgCr", validHash, "100", "/usr/bin/test"},
		{"Ddsr", validHash, "99990", "/"},
	}

	t.Run("valid", func(t *testing.T) {
		m := Manifest{}
		for _, line := range validManifestLines {
			if err := readManifestFileEntry(line, &m); err != nil {
				t.Errorf("failed to read manifest line: %v", err)
			}
		}

		for _, f := range m.Files {
			if f.Type == 0 || f.Status == 0 || f.Modifier == 0 || !f.Rename {
				t.Error("failed to set flag from manifest line")
			}
		}
	})

	invalidHash := "1234567890abcdef1234567890"
	invalidManifestLines := [][]string{
		{"..i.", validHash, "10", "/usr/testfile"},
		{"...", validHash, "10", "/usr/testfile"},
		{"FgCr", invalidHash, "100", "/usr/bin/test"},
		{"Ddsr", validHash, "i", "/"},
	}

	for _, line := range invalidManifestLines {
		t.Run("valid", func(t *testing.T) {
			m := Manifest{}
			if err := readManifestFileEntry(line, &m); err == nil {
				t.Error("readManifestFileEntry did not fail with invalid input")
			}
		})
	}
}

func TestCheckValidManifestHeader(t *testing.T) {
	m := Manifest{
		Header: ManifestHeader{
			Format:      10,
			Version:     100,
			Previous:    90,
			FileCount:   553,
			ContentSize: 100000,
			TimeStamp:   time.Unix(1000, 0),
			// does not fail when includes not added
		},
	}

	if err := m.CheckHeaderIsValid(); err != nil {
		t.Error("CheckHeaderIsValid returned error for valid header")
	}
}

func TestCheckInvalidManifestHeaders(t *testing.T) {
	zeroTime := time.Time{}

	tests := []struct {
		name   string
		header ManifestHeader
	}{
		{"format not set", ManifestHeader{0, 100, 90, 553, time.Unix(1000, 0), 100000, nil}},
		{"version zero", ManifestHeader{10, 0, 90, 553, time.Unix(1000, 0), 100000, nil}},
		{"no files", ManifestHeader{10, 100, 90, 0, time.Unix(1000, 0), 100000, nil}},
		{"no timestamp", ManifestHeader{10, 100, 90, 553, zeroTime, 100000, nil}},
		{"zero contentsize", ManifestHeader{10, 100, 90, 553, time.Unix(1000, 0), 0, nil}},
		{"version smaller than previous", ManifestHeader{10, 100, 110, 553, time.Unix(1000, 0), 100000, nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Manifest{Header: tt.header}
			if err := m.CheckHeaderIsValid(); err == nil {
				t.Error("CheckHeaderIsValid did not return an error on invalid header")
			}
		})
	}
}

func TestReadManifestFromFileGood(t *testing.T) {
	path := "testdata/manifest.good"
	var m Manifest
	if err := m.ReadManifestFromFile(path); err != nil {
		t.Error(err)
	}

	if expected := uint(21); m.Header.Format != expected {
		t.Errorf("Expected manifest format %d, got %d", expected, m.Header.Format)
	}

	if len(m.Files) == 0 {
		t.Error("ReadManifestFromFile did not add file entries to the file list")
	}
}

func TestInvalidManifests(t *testing.T) {
	files, err := filepath.Glob("testdata/invalid_manifests/*")
	if err != nil {
		t.Errorf("error while reading testdata: %s", err)
	}
	if len(files) == 0 {
		t.Error("no files available for this test")
	}
	for _, name := range files {
		t.Run(path.Base(name), func(t *testing.T) {
			var m Manifest
			if err := m.ReadManifestFromFile(name); err == nil {
				t.Error("ReadManifestFromFile did not raise error for invalid manifest")
			}
		})
	}
}

func compareFiles(file1path string, file2path string) (bool, error) {
	var err error
	var f1Stat, f2Stat os.FileInfo
	var f1, f2 *os.File

	chunkSize := 65536

	f1Stat, err = os.Lstat(file1path)
	if err != nil {
		return false, err
	}

	f2Stat, err = os.Lstat(file2path)
	if err != nil {
		return false, err
	}

	if f1Stat.Size() != f2Stat.Size() {
		return false, nil
	}

	f1, err = os.Open(file1path)
	if err != nil {
		return false, err
	}
	defer f1.Close()

	f2, err = os.Open(file2path)
	if err != nil {
		return false, err
	}
	defer f2.Close()

	b1 := bufio.NewReader(f1)
	b2 := bufio.NewReader(f2)
	for {
		bytesRead1 := make([]byte, chunkSize)
		b1BytesIn, err1 := b1.Read(bytesRead1)

		bytesRead2 := make([]byte, chunkSize)
		b2BytesIn, err2 := b2.Read(bytesRead2)

		if b1BytesIn != b2BytesIn {
			return false, nil
		}

		if err1 != nil || err2 != nil {
			if err1 == io.EOF && err2 == io.EOF {
				return true, nil
			} else if err1 == io.EOF || err2 == io.EOF {
				return false, nil
			} else {
				return false, fmt.Errorf("%v - %v", err1, err2)
			}
		}

		if !bytes.Equal(bytesRead1, bytesRead2) {
			return false, nil
		}
	}
}

func TestWriteManifestFile(t *testing.T) {
	path := "testdata/manifest.good"

	var m Manifest
	if err := m.ReadManifestFromFile(path); err != nil {
		t.Fatal(err)
	}

	if len(m.Files) == 0 {
		t.Fatal("ReadManifestFromFile did not add file entried to the file list")
	}

	f, err := ioutil.TempFile("testdata", "manifest.result")
	if err != nil {
		t.Fatal("unable to open file for write")
	}
	defer os.Remove(f.Name())

	newpath := f.Name()
	if err := m.WriteManifestFile(newpath); err != nil {
		t.Error(err)
	}

	match, err := compareFiles(path, newpath)
	if err != nil {
		t.Fatal("unable to compare old and new manifest")
	}

	if !match {
		t.Fatalf("generated %v did not match read %v file", newpath, path)
	}
}

func TestWriteManifestFileBadHeader(t *testing.T) {
	m := Manifest{Header: ManifestHeader{}}

	f, err := ioutil.TempFile("testdata", "manifest.result")
	if err != nil {
		t.Fatal("unable to open file for write")
	}
	defer os.Remove(f.Name())

	path := f.Name()
	if err = m.WriteManifestFile(path); err == nil {
		t.Error("WriteManifestFile did not fail on invalid header")
	}

	if err = os.Remove(path); err != nil {
		t.Error("unable to remove file, did it not close properly?")
	}
}

func TestSortFilesName(t *testing.T) {
	m := Manifest{
		Files: []*File{
			{Name: "c"},
			{Name: "b"},
			{Name: "d"},
			{Name: "a"},
			{Name: "f"},
			{Name: "fa"},
			{Name: "ba"},
		},
	}

	expectedNames := []string{"a", "b", "ba", "c", "d", "f", "fa"}
	mResult := m
	mResult.sortFilesName()
	for i, f := range mResult.Files {
		if f.Name != expectedNames[i] {
			t.Error("manifest files were not sorted correctly")
		}
	}
}

func TestSortFilesVersionName(t *testing.T) {
	m := Manifest{
		Files: []*File{
			{Name: "z", Version: 20},
			{Name: "x", Version: 20},
			{Name: "u", Version: 10},
			{Name: "qa", Version: 30},
			{Name: "qs", Version: 10},
			{Name: "r", Version: 40},
			{Name: "m", Version: 40},
		},
	}

	expectedNames := []string{"qs", "u", "x", "z", "qa", "m", "r"}
	mResult := m
	mResult.sortFilesVersionName()
	for i, f := range mResult.Files {
		if f.Name != expectedNames[i] {
			t.Error("manifest files were not sorted correctly")
		}
	}
}

func TestAddDeleted(t *testing.T) {
	mOld := Manifest{
		DeletedFiles: []*File{
			{Name: "1"},
			{Name: "2"},
			{Name: "3"},
			{Name: "4"},
		},
	}

	mNew := Manifest{
		Files: []*File{
			{Name: "1"},
			{Name: "3"},
			{Name: "5"},
		},
	}

	expectedFileNames := []string{"1", "2", "3", "4", "5"}
	expectedDeletedFileNames := []string{"2", "4"}

	mNew.addDeleted(&mOld)
	// sort to easily compare
	mNew.sortFilesName()
	for i, f := range mNew.Files {
		if f.Name != expectedFileNames[i] {
			t.Errorf("%v did not match expected %v", f.Name, expectedFileNames[i])
		}
	}

	for i, f := range mNew.DeletedFiles {
		if f.Name != expectedDeletedFileNames[i] {
			t.Errorf("%v did not match expected %v", f.Name, expectedDeletedFileNames[i])
		}
	}
}

func TestLinkPeersAndChange(t *testing.T) {
	mOld := Manifest{
		Files: []*File{
			{Name: "1", Status: statusUnset},
			{Name: "2", Status: statusDeleted},
			{Name: "3", Status: statusGhosted},
			{Name: "4", Status: statusUnset},
			{Name: "5", Status: statusUnset, Hash: 1},
		},
	}

	mNew := Manifest{
		Files: []*File{
			{Name: "1", Status: statusUnset},
			{Name: "2", Status: statusDeleted},
			{Name: "3", Status: statusUnset},
			{Name: "5", Status: statusUnset, Hash: 2},
			{Name: "6", Status: statusUnset},
		},
	}

	testCases := map[string]struct {
		hasPeer  bool
		expected string
	}{
		"1": {true, "1"},
		"2": {false, ""},
		"3": {false, ""},
		"5": {true, "5"},
		"6": {false, ""},
	}

	if changed := mNew.linkPeersAndChange(&mOld); changed != 1 {
		t.Errorf("%v files detected as changed when only 1 was expected", changed)
	}

	for _, f := range mNew.Files {
		if testCases[f.Name].hasPeer {
			if f.DeltaPeer == nil {
				t.Errorf("File %v does not have delta peer when expected", f.Name)
			}

			if f.DeltaPeer.Name != testCases[f.Name].expected {
				t.Errorf("File %v has %v delta peer when %v is expected",
					f.Name,
					f.DeltaPeer.Name,
					testCases[f.Name].expected)
			}
		}
	}
}

func TestFilesAdded(t *testing.T) {
	mOld := Manifest{
		Files: []*File{
			{Name: "1"},
			{Name: "2"},
			{Name: "4"},
		},
	}

	mNew := Manifest{
		Files: []*File{
			{Name: "1"},
			{Name: "2"},
			{Name: "3"},
			{Name: "4"},
			{Name: "5"},
		},
	}

	if added := mNew.filesAdded(&mOld); added != 2 {
		t.Errorf("filesAdded detected %v added files when 2 was expected", added)
	}
}

func TestNewDeleted(t *testing.T) {
	mOld := Manifest{
		Files: []*File{
			{Name: "1"},
			{Name: "2", Status: statusDeleted},
			{Name: "4"},
		},
	}

	mNew := Manifest{
		DeletedFiles: []*File{
			{Name: "1"},
			{Name: "2"},
			{Name: "3"},
		},
	}

	// file 1 is the only new deleted file
	if deleted := mNew.newDeleted(&mOld); deleted != 1 {
		t.Errorf("newDeleted detected %v new deleted files when 1 was expected", deleted)
	}
}

func TestHasTypeChanges(t *testing.T) {
	mUnchanged := Manifest{
		Files: []*File{
			{ // no delta peer, no type change
				Name:      "1",
				Type:      typeFile,
				Status:    statusUnset,
				DeltaPeer: nil,
			},
			{ // same type, no type change
				Name:   "2",
				Type:   typeFile,
				Status: statusUnset,
				DeltaPeer: &File{
					Name:   "2",
					Type:   typeFile,
					Status: statusUnset,
				},
			},
			{ // File -> Link OK, no change reported
				Name:   "3",
				Type:   typeLink,
				Status: statusUnset,
				DeltaPeer: &File{
					Name:   "3",
					Type:   typeFile,
					Status: statusUnset,
				},
			},
			{ // File -> Directory OK, no change reported
				Name:   "4",
				Type:   typeDirectory,
				Status: statusUnset,
				DeltaPeer: &File{
					Name:   "4",
					Type:   typeFile,
					Status: statusUnset,
				},
			},
			{ // Link -> File OK, no change reported
				Name:   "5",
				Type:   typeFile,
				Status: statusUnset,
				DeltaPeer: &File{
					Name:   "5",
					Type:   typeLink,
					Status: statusUnset,
				},
			},
			{ // Link -> Directory OK, no change reported
				Name:   "6",
				Type:   typeDirectory,
				Status: statusUnset,
				DeltaPeer: &File{
					Name:   "6",
					Type:   typeLink,
					Status: statusUnset,
				},
			},
			{ // file deleted, no type change reported
				Name:   "7",
				Type:   typeFile,
				Status: statusDeleted,
				DeltaPeer: &File{
					Name:   "7",
					Type:   typeLink,
					Status: statusUnset,
				},
			},
			{ // delta peer deleted, no type change reported
				Name:   "8",
				Type:   typeFile,
				Status: statusUnset,
				DeltaPeer: &File{
					Name:   "8",
					Type:   typeLink,
					Status: statusDeleted,
				},
			},
		},
	}
	msChanged := []Manifest{
		Manifest{
			Files: []*File{ // Directory -> File TYPE CHANGE
				&File{
					Name:   "1",
					Type:   typeFile,
					Status: statusUnset,
					DeltaPeer: &File{
						Name:   "1",
						Type:   typeDirectory,
						Status: statusUnset,
					},
				},
			},
		},
		Manifest{
			Files: []*File{ // Directory -> Link TYPE CHANGE
				&File{
					Name:   "2",
					Type:   typeLink,
					Status: statusUnset,
					DeltaPeer: &File{
						Name:   "2",
						Type:   typeDirectory,
						Status: statusUnset,
					},
				},
			},
		},
	}

	if mUnchanged.hasTypeChanges() {
		t.Error("Manifest with no type changes detected to have type changes")
	}

	for _, m := range msChanged {
		if !m.hasTypeChanges() {
			t.Error("Manifest with type changes detected to have no type changes")
		}
	}
}