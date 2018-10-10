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
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/minio/sha256-simd"
)

// Hashval is the integer index of the interned hash
type Hashval int

// AllZeroHash is the string representation of a zero value hash
var AllZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Hashes is a global map of indices to hashes
var Hashes = []*string{&AllZeroHash}
var invHash = map[string]Hashval{AllZeroHash: 0}
var rwMutex sync.RWMutex

// internHash adds only new hashes to the Hashes slice and returns the index at
// which they are located
func internHash(hash string) Hashval {
	// Many reader locks can be acquired at the same time
	rwMutex.RLock()
	if key, ok := invHash[hash]; ok {
		rwMutex.RUnlock()
		return key
	}
	rwMutex.RUnlock()
	// We need to grab a full lock now and check that it still does not exist
	// because by the time we grab a lock and append, another thread could have
	// already added the same hash since many files can overlap. The lock says
	// no more reader locks can be acquired, and waits until all are released
	// before taking the lock continuing forward with the check and appending.
	rwMutex.Lock()
	if key, ok := invHash[hash]; ok {
		rwMutex.Unlock()
		return key
	}
	Hashes = append(Hashes, &hash)
	key := Hashval(len(Hashes) - 1)
	invHash[hash] = key
	rwMutex.Unlock()
	return key
}

func (h Hashval) String() string {
	return *Hashes[int(h)]
}

// HashEquals trivial equality function for Hashval
func HashEquals(h1 Hashval, h2 Hashval) bool {
	return h1 == h2
}

// Hashcalc returns the swupd hash for the given file
func Hashcalc(filename string) (Hashval, error) {
	r, err := GetHashForFile(filename)
	if err != nil {
		return 0, err
	}
	return internHash(r), nil
}

// set fills in a buffer with an int in little endian order.
func set(out []byte, in int64) {
	for i := range out {
		out[i] = byte(in & 0xff)
		in >>= 8
	}
}

// HashFileInfo contains the metadata of a file that is included as
// part of the swupd hash.
type HashFileInfo struct {
	Mode     uint32
	UID      uint32
	GID      uint32
	Size     int64
	Linkname string
}

// GetStats
func GetStats(info *HashFileInfo) ([40]byte, error) {
	var data []byte
	var b [40]byte
	switch info.Mode & syscall.S_IFMT {
	case syscall.S_IFREG:
	case syscall.S_IFDIR:
		info.Size = 0
		data = []byte("DIRECTORY")
	case syscall.S_IFLNK:
		//info.Mode = 0
		data = []byte(info.Linkname)
		info.Size = int64(len(data))
	default:
		return b, fmt.Errorf("invalid")
	}

	stat := [40]byte{}
	set(stat[0:8], int64(info.Mode))
	set(stat[8:16], int64(info.UID))
	set(stat[16:24], int64(info.GID))
	// 24:32 is rdev, but this is always zero.
	set(stat[32:40], info.Size)

	return stat, nil
}

// GetHashForFile calculate the swupd hash for a file in the disk.
func GetHashForFile(filename string) (string, error) {
	var info syscall.Stat_t
	var err error
	if err = syscall.Lstat(filename, &info); err != nil {
		return "", fmt.Errorf("error statting file '%s' %v", filename, err)
	}

	hashInfo := &HashFileInfo{
		Mode: info.Mode,
		UID:  info.Uid,
		GID:  info.Gid,
		Size: info.Size,
	}

	stat, err := GetStats(hashInfo)
	if err != nil {
		return "", fmt.Errorf("error creating hash for file %s: %s", filename, err)
	}

	h := sha256.New()
	switch hashInfo.Mode & syscall.S_IFMT {
	case syscall.S_IFREG:
		f, err := os.Open(filename)
		if err != nil {
			return "", fmt.Errorf("read error for file %s: %s", filename, err)
		}
		_, err = io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			return "", fmt.Errorf("error hashing file %s: %s", filename, err)
		}
	case syscall.S_IFDIR:
		info.Size = 0
		h.Write([]byte("DIRECTORY"))
	case syscall.S_IFLNK:
		h.Write([]byte(hashInfo.Linkname))
	default:
		return "", fmt.Errorf("invalid")
	}

	h.Write(stat[:])

	return string(h.Sum(nil)), nil
}

// GetHashForBytes calculate the hash for data already in memory and the
// associated metadata.
func GetHashForBytes(info *HashFileInfo, data []byte) (string, error) {
	stat, err := GetStats(info)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	switch info.Mode & syscall.S_IFMT {
	case syscall.S_IFREG:
		if data != nil {
			h.Write(data)
		}
	case syscall.S_IFDIR:
		info.Size = 0
		h.Write([]byte("DIRECTORY"))
	case syscall.S_IFLNK:
		h.Write([]byte(info.Linkname))
	default:
		return "", fmt.Errorf("invalid")
	}

	h.Write(stat[:])
	return string(h.Sum(nil)), nil
}
