// Copyright 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package swupd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const illegalChars = ";&|*`/<>\\\"'"

func filenameBlacklisted(fname string) bool {
	return strings.ContainsAny(fname, illegalChars)
}

// createFileRecord creates a manifest File entry from a file
// this function sets the Name, Info, Type, and Hash fields
// the Version field is additionally set using the global toVersion variable
func (m *Manifest) createFileRecord(rootPath string, path string, fi os.FileInfo) error {
	var file *File
	fname := strings.TrimPrefix(path, rootPath)
	if fname == "" {
		return nil
	}

	if filenameBlacklisted(filepath.Base(fname)) {
		return fmt.Errorf("%s is a blacklisted file name\n", fname)
	}

	file = &File{
		Name: fname,
		Info: fi,
	}

	switch mode := fi.Mode(); {
	case mode.IsRegular():
		file.Type = typeFile
	case mode.IsDir():
		file.Type = typeDirectory
	case mode&os.ModeSymlink != 0:
		file.Type = typeLink
	default:
		return fmt.Errorf("%v is an unsupported file type\n", file.Name)
	}

	fh, err := Hashcalc(rootPath + file.Name)
	if err != nil {
		return fmt.Errorf("hash calculation error: %v", err)
	}

	file.Hash = fh

	m.Files = append(m.Files, file)
	m.Header.ContentSize += uint64(fi.Size())

	return nil
}

// createManifestRecord wraps createFileRecord to create a Manifest record for a MoM
func (m *Manifest) createManifestRecord(rootPath string, path string, fi os.FileInfo, version uint32) error {
	if err := m.createFileRecord(rootPath, path, fi); err != nil {
		if strings.Contains(err.Error(), "hash calculation error") {
			return err
		}
		fmt.Fprint(os.Stderr, err)
	}

	// remove leading "/" from manifest record
	f := m.Files[len(m.Files)-1]
	f.Name = strings.TrimLeft(f.Name, "/")
	f.Type = typeManifest
	f.Version = version
	return nil
}

func (m *Manifest) addFilesFromChroot(rootPath string) error {
	if _, err := os.Stat(rootPath); os.IsNotExist(err) {
		return err
	}

	err := filepath.Walk(rootPath, func(path string, fi os.FileInfo, err error) error {
		err = m.createFileRecord(rootPath, path, fi)
		if err != nil {
			if strings.Contains(err.Error(), "hash calculation error") {
				return err
			}
			fmt.Fprint(os.Stderr, err)
		}
		return nil
	})

	return err
}

func exists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}

	return true
}
