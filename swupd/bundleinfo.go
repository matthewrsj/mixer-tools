// Copyright 2018 Intel Corporation
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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type bundleInfo struct {
	Name           string
	Filename       string
	DirectIncludes []string
	DirectPackages []string
	AllPackages    []string
	Files          []string
}

func (m *Manifest) getBundleInfo(path string) error {
	var err error
	if _, err = os.Stat(path); os.IsNotExist(err) {
		basePath := filepath.Dir(path)
		err = m.addFilesFromChroot(filepath.Join(filepath.Dir(path), m.Name))
		if err != nil {
			return err
		}
		for _, f := range m.Files {
			m.bundleInfo.Files = append(m.bundleInfo.Files, f.Name)
		}
		m.Files = []*File{}

		includes := []string{}
		includes, err = readIncludesFile(filepath.Join(basePath, m.Name+"-includes"))
		if err != nil {
			return err
		}
		m.bundleInfo.DirectIncludes = includes
		return nil
	}

	biBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	return json.Unmarshal(biBytes, &m.bundleInfo)
}

func (m *Manifest) addFilesFromBundleInfo(c config, version uint32) error {
	for _, fpath := range m.bundleInfo.Files {
		chrootDir := filepath.Join(c.imageBase, fmt.Sprint(version), "full")
		fullPath := filepath.Join(chrootDir, fpath)
		fi, err := os.Lstat(fullPath)
		if err != nil {
			return err
		}

		err = m.createFileRecord(chrootDir, fpath, fi)
		if err != nil {
			if strings.Contains(err.Error(), "hash calculation error") {
				return err
			}
			fmt.Fprintf(os.Stderr, "Warning: %s\n", err)
		}
	}

	return nil
}

func (m *Manifest) readIncludesFromBundleInfo(bundles []*Manifest) error {
	includes := []*Manifest{}
	// os-core is added as an include for every bundle
	// handle it manually so we don't have to rely on the includes list having it
	for _, b := range bundles {
		if b.Name == "os-core" {
			includes = append(includes, b)
		}
	}

	for _, bn := range m.bundleInfo.DirectIncludes {
		// just add this one blindly since it is processed later
		if bn == indexBundle {
			includes = append(includes, &Manifest{Name: indexBundle})
			continue
		}

		if bn == "os-core" {
			// already added this one
			continue
		}

		for _, b := range bundles {
			if bn == b.Name {
				includes = append(includes, b)
			}
		}
	}

	m.Header.Includes = includes
	return nil
}
