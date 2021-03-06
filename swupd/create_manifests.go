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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// UpdateInfo contains the meta information for the current update
type UpdateInfo struct {
	oldFormat   uint
	format      uint
	lastVersion uint32
	version     uint32
	bundles     []string
	timeStamp   time.Time
}

func initBuildEnv(c config) error {
	tmpDir := filepath.Join(c.stateDir, "temp")
	// remove old directory
	if err := os.RemoveAll(tmpDir); err != nil {
		return err
	}

	// create new one
	return os.Mkdir(tmpDir, os.ModePerm)
}

// initBuildDirs creates the following directory structure
// StateDir/
//    image/
//        <version>/
//            <bundle1>/
//            ...
//    LAST_VER
func initBuildDirs(version uint32, groups []string, imageBase string) error {
	verDir := filepath.Join(imageBase, fmt.Sprint(version))
	for _, bundle := range groups {
		if err := os.MkdirAll(filepath.Join(verDir, bundle), 0755); err != nil {
			return err
		}
	}

	return nil
}

func processBundles(ui UpdateInfo, c config) ([]*Manifest, error) {
	newManifests := []*Manifest{}
	for _, bundle := range ui.bundles {
		oldMPath := filepath.Join(c.outputDir, fmt.Sprint(ui.lastVersion), "Manifest."+bundle)
		oldM, err := ParseManifestFile(oldMPath)
		if err != nil {
			// throw away read manifest if it is invalid
			if strings.Contains(err.Error(), "invalid manifest") {
				fmt.Fprintf(os.Stderr, "%s: %s\n", oldM.Name, err)
			}
			oldM = &Manifest{}
		}

		newM := &Manifest{
			Header: ManifestHeader{
				Format:    ui.format,
				Version:   ui.version,
				Previous:  ui.lastVersion,
				TimeStamp: ui.timeStamp,
			},
			Name: bundle,
		}

		newMChroot := filepath.Join(c.imageBase, fmt.Sprint(ui.version), newM.Name)
		if err := newM.addFilesFromChroot(newMChroot); err != nil {
			return newManifests, err
		}

		if ui.oldFormat == ui.format {
			newM.addDeleted(oldM)
		}

		changedIncludes := compareIncludes(newM, oldM)
		changedFiles := newM.linkPeersAndChange(oldM)
		added := newM.filesAdded(oldM)
		deleted := newM.newDeleted(oldM)
		if changedFiles == 0 && added == 0 && deleted == 0 && !changedIncludes {
			continue
		}

		if c.debuginfo.banned {
			newM.removeDebuginfo(c.debuginfo)
		}

		// detect type changes
		// fail out here if a type change is detected since this is not yet supported in client
		if newM.hasUnsupportedTypeChanges() {
			return newManifests, errors.New("type changes not yet supported")
		}

		// detect modifier flag for all files in the manifest
		newM.applyHeuristics()

		// if we get this far we need to actually write this manifest because it has changes
		newManifests = append(newManifests, newM)
	}

	for _, bundle := range newManifests {
		if bundle.Name != "os-core" && bundle.Name != "full" {
			// read in bundle includes
			if err := bundle.readIncludes(newManifests, c); err != nil {
				return newManifests, err
			}

			// subtract manifests
			bundle.subtractManifests(bundle)
		}
	}

	for _, bundle := range newManifests {
		// sort manifest by version (then by filename)
		// this must be done after subtractManifests has been done for all manifests
		// because subtractManifests sorts the file lists by filename alone
		bundle.sortFilesVersionName()
		bundle.Header.FileCount = uint32(len(bundle.Files))
	}

	return newManifests, nil
}

// CreateManifests creates update manifests for changed and added bundles for <version>
func CreateManifests(version uint32, minVersion bool, format uint, statedir string) error {
	var err error
	var c config
	c, err = getConfig(statedir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Found server.ini, but was unable to read it. "+
			"Continuing with default configuration\n")
	}

	if err = initBuildEnv(c); err != nil {
		return err
	}

	var groups []string
	if groups, err = readGroupsINI(filepath.Join(c.stateDir, "groups.ini")); err != nil {
		return err
	}

	groups = append(groups, "full")

	var lastVersion uint32
	lastVersion, err = readLastVerFile(filepath.Join(c.imageBase, "LAST_VER"))
	if err != nil {
		return err
	}

	oldFullManifestPath := filepath.Join(c.outputDir, fmt.Sprint(lastVersion), "Manifest.full")
	oldFullManifest, err := ParseManifestFile(oldFullManifestPath)
	if err != nil {
		// throw away read manifest if it is invalid
		if strings.Contains(err.Error(), "invalid manifest") {
			fmt.Fprintf(os.Stderr, "full: %s\n", err)
		}
		oldFullManifest = &Manifest{}
	}

	if oldFullManifest.Header.Format > format {
		return fmt.Errorf("new format %v is lower than old format %v", format, oldFullManifest.Header.Format)
	}

	if err = initBuildDirs(version, groups, c.imageBase); err != nil {
		return err
	}

	// create new chroot from all bundle chroots
	// TODO: this should be its own thing that an earlier step in mixer does
	if err = createNewFullChroot(version, groups, c.imageBase); err != nil {
		return err
	}

	timeStamp := time.Now()
	oldMoMPath := filepath.Join(c.stateDir, fmt.Sprint(lastVersion), "Manifest.MoM")
	oldMoM, err := ParseManifestFile(oldMoMPath)
	if err != nil {
		// throw away read manifest if it is invalid
		if strings.Contains(err.Error(), "invalid manifest") {
			fmt.Fprintf(os.Stderr, "MoM: %s\n", err)
		}
		oldMoM = &Manifest{Header: ManifestHeader{Version: lastVersion}}
	}

	oldFormat := oldMoM.Header.Format

	// PROCESS BUNDLES
	ui := UpdateInfo{
		oldFormat:   oldFormat,
		format:      format,
		lastVersion: lastVersion,
		version:     version,
		bundles:     groups,
		timeStamp:   timeStamp,
	}
	var newManifests []*Manifest
	if newManifests, err = processBundles(ui, c); err != nil {
		return err
	}

	verOutput := filepath.Join(c.outputDir, fmt.Sprint(version))
	if err = os.MkdirAll(verOutput, 0755); err != nil {
		return err
	}

	newMoM := Manifest{
		Name: "MoM",
		Header: ManifestHeader{
			Format:    format,
			Version:   version,
			Previous:  lastVersion,
			TimeStamp: timeStamp,
		},
	}

	for _, bMan := range newManifests {
		manPath := filepath.Join(verOutput, "Manifest."+bMan.Name)
		if err = bMan.WriteManifestFile(manPath); err != nil {
			return err
		}

		var fi os.FileInfo
		if fi, err = os.Lstat(manPath); err != nil {
			return err
		}

		if newMoM.createManifestRecord(verOutput, manPath, fi, version); err != nil {
			return err
		}
	}

	for _, m := range oldMoM.Files {
		if match := m.findFileNameInSlice(newMoM.Files); match != nil {
			newMoM.Files = append(newMoM.Files, match)
		}
	}

	newMoM.Header.FileCount = uint32(len(newMoM.Files))
	newMoM.sortFilesVersionName()

	// write MoM
	if err = newMoM.WriteManifestFile(filepath.Join(verOutput, "Manifest.MoM")); err != nil {
		return err
	}

	return nil
}
