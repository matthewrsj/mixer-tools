package swupd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

// #include <unistd.h>
// #include <stdlib.h>
// #include <stdint.h>
// #include <sys/stat.h>
// uint64_t get_ifmt() { return S_IFMT; }
// uint64_t get_ifreg() { return S_IFREG; }
// uint64_t get_ifdir() { return S_IFDIR; }
// uint64_t get_iflnk() { return S_IFLNK; }
import "C"
import "unsafe"

type hashval int

// Defined as Go types to ensure that we can do bit operations with it.
var s_ifmt C.uint64_t
var s_ifreg C.uint64_t
var s_ifdir C.uint64_t
var s_iflnk C.uint64_t

func init() {
	s_ifmt = C.get_ifmt()
	s_ifreg = C.get_ifreg()
	s_ifdir = C.get_ifdir()
	s_iflnk = C.get_iflnk()
}

var AllZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Hashes is a global map of indices to hashes
var Hashes = []*string{&AllZeroHash}
var invHash = map[string]hashval{AllZeroHash: 0}

// internHash adds only new hashes to the Hashes slice and returns the index at
// which they are located
func internHash(hash string) hashval {
	if key, ok := invHash[hash]; ok {
		return key
	}
	Hashes = append(Hashes, &hash)
	key := hashval(len(Hashes) - 1)
	invHash[hash] = key
	return key
}

func (h hashval) String() string {
	return *Hashes[int(h)]
}

// HashEquals trivial equality function for hashval
func HashEquals(h1 hashval, h2 hashval) bool {
	return h1 == h2
}

// Hashcalc returns the swupd hash for the given file
func Hashcalc(filename string) (hashval, error) {
	var data []byte
	var err error
	var info C.struct_stat
	cs := C.CString(filename)
	defer C.free(unsafe.Pointer(cs))
	if errno := C.lstat(cs, &info); errno != 0 {
		return 0, fmt.Errorf("Error stating file '%s' %v\n", filename, errno)
	}
	file_type := C.uint64_t(info.st_mode) & s_ifmt
	switch file_type {
	case s_ifreg: // Regular file
		data, err = ioutil.ReadFile(filename)
		if err != nil {
			return 0, fmt.Errorf("Read error for '%s' %v\n", filename, err)
		}
	case s_ifdir: // Directory
		info.st_size = 0
		data = []byte("DIRECTORY") // fixed magic string
	case s_iflnk: // Symbolic link
		info.st_mode = 0
		var target string
		target, err = os.Readlink(filename)
		if err != nil {
			return 0, fmt.Errorf("Error readlink file '%s' %v\n", filename, err)
		}
		data = []byte(target)
	default:
		return 0, fmt.Errorf("%s is not a file, directory or symlink %o", filename, file_type)
	}
	r := internHash(genHash(info, data))
	return r, nil
}

// genHash generates hash string from butchered Stat_t and data
// Expects that its callers have validated the arguments
func genHash(info C.struct_stat, data []byte) string {
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
// The C.struct_stat has been butchered
func hmacComputeKey(info C.struct_stat) []byte {
	// Create the key
	updatestat := [40]byte{}
	set(updatestat[0:8], int64(info.st_mode))
	set(updatestat[8:16], int64(info.st_uid))
	set(updatestat[16:24], int64(info.st_gid))
	// 24:32 is rdev, but this is always zero
	set(updatestat[24:32], 0)
	set(updatestat[32:40], int64(info.st_size))
	// fmt.Printf("key is %v\n", updatestat)
	key := hmacSha256ForData(updatestat[:], nil)
	return key
}
