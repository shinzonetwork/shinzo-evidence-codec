package merkle

import (
	"encoding/hex"
	"testing"
)

// Vectors from github.com/transparency-dev/merkle, testonly/constants.go.
// roots[n] is the root of the first n leaves.
func TestRoot(t *testing.T) {
	t.Parallel()
	leaves := [][]byte{
		hexBytes(t, ""),
		hexBytes(t, "00"),
		hexBytes(t, "10"),
		hexBytes(t, "2021"),
		hexBytes(t, "3031"),
		hexBytes(t, "40414243"),
		hexBytes(t, "5051525354555657"),
		hexBytes(t, "606162636465666768696a6b6c6d6e6f"),
	}
	roots := []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	for n, want := range roots {
		got := Root(leaves[:n])
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("Root of %d leaves = %x, want %s", n, got, want)
		}
	}
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
