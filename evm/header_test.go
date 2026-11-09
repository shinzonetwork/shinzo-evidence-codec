package evm

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// headerFixture is an eth_getBlockByNumber answer from the generator's testdata at 42890f54. BSC nodes also report
// milliTimestamp.
type headerFixture struct {
	chain          string
	Hash           common.Hash     `json:"hash"`
	ParentHash     common.Hash     `json:"parentHash"`
	StateRoot      common.Hash     `json:"stateRoot"`
	TxRoot         common.Hash     `json:"transactionsRoot"`
	ReceiptsRoot   common.Hash     `json:"receiptsRoot"`
	MixHash        common.Hash     `json:"mixHash"`
	Number         hexutil.Uint64  `json:"number"`
	Timestamp      hexutil.Uint64  `json:"timestamp"`
	MilliTimestamp *hexutil.Uint64 `json:"milliTimestamp"`
	raw            []byte
}

func TestHeaderFromRaw(t *testing.T) {
	t.Parallel()
	for _, f := range headerFixtures(t) {
		h, err := HeaderFromRaw(f.raw)
		if err != nil {
			t.Fatal(err)
		}
		want := Header{
			Hash:             f.Hash,
			ParentHash:       f.ParentHash,
			StateRoot:        f.StateRoot,
			TransactionsRoot: f.TxRoot,
			ReceiptsRoot:     f.ReceiptsRoot,
			Number:           uint64(f.Number),
			Time:             uint64(f.Timestamp),
			MixDigest:        f.MixHash,
		}
		if h != want {
			t.Errorf("%s: HeaderFromRaw =\n%+v\nwant\n%+v", f.chain, h, want)
		}
	}
}

// A field appended by a later fork must not change what is read.
func TestHeaderFromRawAppendedField(t *testing.T) {
	t.Parallel()
	f := headerFixtures(t)[0]
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(f.raw, &fields); err != nil {
		t.Fatal(err)
	}
	longer, err := rlp.EncodeToBytes(append(fields, rlp.RawValue{0x01}))
	if err != nil {
		t.Fatal(err)
	}
	h, err := HeaderFromRaw(longer)
	if err != nil {
		t.Fatal(err)
	}
	if h.ParentHash != f.ParentHash || h.Number != uint64(f.Number) || h.Time != uint64(f.Timestamp) {
		t.Fatalf("HeaderFromRaw with an appended field = %+v", h)
	}
}

func TestHeaderFromRawShort(t *testing.T) {
	t.Parallel()
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(headerFixtures(t)[0].raw, &fields); err != nil {
		t.Fatal(err)
	}
	short, err := rlp.EncodeToBytes(fields[:mixDigestField])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := HeaderFromRaw(short); !errors.Is(err, ErrHeaderShort) {
		t.Fatalf("HeaderFromRaw = %v, want %v", err, ErrHeaderShort)
	}
}

// The BSC fixture's milliTimestamp comes from the node; Ethereum's mixHash is a random value and must be ignored.
func TestBlockTime(t *testing.T) {
	t.Parallel()
	for _, f := range headerFixtures(t) {
		h, err := HeaderFromRaw(f.raw)
		if err != nil {
			t.Fatal(err)
		}
		want := uint64(f.Timestamp) * 1000
		if f.MilliTimestamp != nil {
			want = uint64(*f.MilliTimestamp)
		}
		got, err := BlockTime(f.chain, h)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: BlockTime = %d, want %d", f.chain, got, want)
		}
	}
}

// BSC reads only the low 64 bits of mixHash, so bits above them do not count.
func TestBlockTimeBSCMilliseconds(t *testing.T) {
	t.Parallel()
	highBitsSet := common.BigToHash(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(900)))
	cases := []struct {
		name      string
		mixDigest common.Hash
		want      uint64
		wantErr   error
	}{
		{"999", common.BigToHash(big.NewInt(999)), 7_999, nil},
		{"1000", common.BigToHash(big.NewInt(1000)), 0, ErrMilliseconds},
		{"bits above the low 64", highBitsSet, 7_900, nil},
	}
	for _, tc := range cases {
		got, err := BlockTime(bscMainnet, Header{Time: 7, MixDigest: tc.mixDigest})
		if got != tc.want || !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: BlockTime = %d, %v, want %d, %v", tc.name, got, err, tc.want, tc.wantErr)
		}
	}
}

// headerFixtures returns the fixtures with their raw headers, encoded by go-ethereum from the node's JSON.
func headerFixtures(t *testing.T) []headerFixture {
	t.Helper()
	var fixtures []headerFixture
	for _, file := range []struct{ chain, name string }{
		{"eip155:1", "ethereum-header-26298550.json"},
		{bscMainnet, "bsc-header-130479847.json"},
	} {
		b, err := os.ReadFile(filepath.Join("testdata", file.name))
		if err != nil {
			t.Fatal(err)
		}
		f := headerFixture{chain: file.chain}
		var header types.Header
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &header); err != nil {
			t.Fatal(err)
		}
		if f.raw, err = rlp.EncodeToBytes(&header); err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, f)
	}
	return fixtures
}
