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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
)

// Hashval is the integer index of the interned hash
type Hashval int

// AllZeroHash is the string representation of a zero value hash
var AllZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Hashes is a global map of indices to hashes
var Hashes = []*string{&AllZeroHash}
var invHash = map[string]Hashval{AllZeroHash: 0}

// internHash adds only new hashes to the Hashes slice and returns the index at
// which they are located
func internHash(hash string) Hashval {
	if key, ok := invHash[hash]; ok {
		return key
	}
	Hashes = append(Hashes, &hash)
	key := Hashval(len(Hashes) - 1)
	invHash[hash] = key
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
	var info syscall.Stat_t
	var err error
	var data []byte
	if err = syscall.Lstat(filename, &info); err != nil {
		return 0, fmt.Errorf("error statting file '%s' %v", filename, err)
	}
	// Get magic constants out of /usr/include/bits/stat.h
	switch info.Mode & syscall.S_IFMT {
	case syscall.S_IFREG: // Regular file
		data, err = ioutil.ReadFile(filename)
		if err != nil {
			return 0, fmt.Errorf("read error for '%s' %v", filename, err)
		}
	case syscall.S_IFDIR: // Directory
		info.Size = 0
		data = []byte("DIRECTORY") // fixed magic string
	case syscall.S_IFLNK:
		info.Mode = 0
		target, err := os.Readlink(filename)
		if err != nil {
			return 0, fmt.Errorf("error readlink file '%s' %v", filename, err)
		}
		data = []byte(target)
	default:
		return 0, fmt.Errorf("%s is not a file, directory or symlink %o", filename, info.Mode&syscall.S_IFMT)
	}
	r := internHash(genHash(info, data))
	return r, nil
}

// genHash generates hash string from butchered Stat_t and data
// Expects that its callers have validated the arguments
func genHash(info syscall.Stat_t, data []byte) string {
	key := hmacComputeKey(info)
	result := hmacSha256ForData(key, data)
	return string(result[:])
}

// hmacSha256ForData returns an array of 64 ascii hex digits
func hmacSha256ForData(key []byte, data []byte) []byte {
	var result [64]byte

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	hex.Encode(result[:], mac.Sum(nil))
	return result[:]
}

// This is what I want to have for the key
// type updatestat struct {
// 	st_mode uint64
// 	st_uid  uint64
// 	st_gid  uint64
// 	st_rdev uint64
// 	st_size uint64
// }

// set fills in a buffer with an int in little endian order
func set(out []byte, in int64) {
	for i := range out {
		out[i] = byte(in & 0xff)
		in >>= 8
	}
}

// hmacComputeKey returns what should be an ascii string as an array of byte
// it is really ugly to be compatible with the C implementation. It is not portable
// as the C version isn't portable.
// The syscall.Stat_t has been butchered
func hmacComputeKey(info syscall.Stat_t) []byte {
	// Create the key
	updatestat := [40]byte{}
	set(updatestat[0:8], int64(info.Mode))
	set(updatestat[8:16], int64(info.Uid))
	set(updatestat[16:24], int64(info.Gid))
	// 24:32 is rdev, but this is always zero
	set(updatestat[24:32], 0)
	set(updatestat[32:40], info.Size)
	// fmt.Printf("key is %v\n", updatestat)
	key := hmacSha256ForData(updatestat[:], nil)
	return key
}
