package swupd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/minio/sha256-simd"
)

// Go does not implement UID lookups, because it's Unix-specific
func getUID(fi os.FileInfo) uint32 {
	return fi.Sys().(*syscall.Stat_t).Uid
}

// Go does not implement GID lookups, because it's Unix-specific
func getGID(fi os.FileInfo) uint32 {
	return fi.Sys().(*syscall.Stat_t).Gid
}

// Go does not implement Rdev lookups, because it's Unix-specific
func getRdev(fi os.FileInfo) uint64 {
	return fi.Sys().(*syscall.Stat_t).Rdev
}

func readLinkBytes(file string) ([]byte, error) {
	val, err := os.Readlink(file)
	if err != nil {
		return nil, err
	}
	return []byte(val), nil
}

func calcHash(result *[]byte) string {
	sum := sha256.Sum256(*result)
	return fmt.Sprintf("%x", sum)
}

func addBytes(result *bytes.Buffer, data []byte) {
	result.Write(data)
}

// Compute calculates a SHA256 hash for one regular file, directory, or
// symlink, passed in the first argument. It accounts for file permissions and
// ownership to more uniquely identify files. If no errors occurred, it returns
// the resulting hash as a hexadecimal encoded byte string.
func SimpleHashForFile(file string) (string, error) {
	//var result bytes.Buffer
	var ret []byte
	stat, err := os.Lstat(file)

	if err != nil {
		return "", err
	}

	// First we add boilerplate file metadata, as returned from Lstat()
	s := stat.Size()
	ret = append(ret, byte(stat.Mode()))
	ret = append(ret, byte(getUID(stat)))
	ret = append(ret, byte(getGID(stat)))
	ret = append(ret, byte(getRdev(stat)))
	ret = append(ret, byte(s))

	// Then we add custom data specific to the file type
	var r []byte
	switch mode := stat.Mode(); {
	case mode.IsRegular():
		var f *os.File
		f, err = os.Open(file)
		if err != nil {
			return "", err
		}
		if stat.Size() == 0 {
			r = []byte{}
		} else {
			r, err = syscall.Mmap(int(f.Fd()), 0, int(s), syscall.PROT_READ, syscall.MAP_SHARED)
		}
	case mode&os.ModeSymlink != 0:
		r, err = readLinkBytes(file)
	case mode.IsDir():
		r = []byte("DIRECTORY")
	default:
		return "", errors.New("Unsupported file type")
	}
	if err != nil {
		fmt.Println("Waaaa")
		return "", err
	}
	ret = append(ret, r...)
	// Finally, we calculate the hash of this data
	return calcHash(&ret), nil
}
