package swupd

type hashval int

// Hashes is a global map of indices to hashes
var Hashes = []*string{}
var invHash = make(map[string]hashval)

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
