// Package merkle implements the RFC 9162 Merkle tree hash with SHA-256.
package merkle

import "crypto/sha256"

// Root returns the Merkle tree hash of leaves (RFC 9162, section 2.1.1).
func Root(leaves [][]byte) [sha256.Size]byte {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return sha256.Sum256(append([]byte{0x00}, leaves[0]...))
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	left, right := Root(leaves[:k]), Root(leaves[k:])
	return sha256.Sum256(append(append([]byte{0x01}, left[:]...), right[:]...))
}
