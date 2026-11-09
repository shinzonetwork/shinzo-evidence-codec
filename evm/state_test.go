package evm

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// stateFixture is an eth_getProof answer for USD1's total supply and owner balance, with both values read by eth_call at
// the same block. The files come from shinzo-evidence evm/testdata at 5d43e1a.
type stateFixture struct {
	StateRoot           common.Hash    `json:"stateRoot"`
	Contract            common.Address `json:"contract"`
	SupplySlot          common.Hash    `json:"supplySlot"`
	OwnerBalanceSlot    common.Hash    `json:"ownerBalanceSlot"`
	EthCallTotalSupply  hexutil.Bytes  `json:"ethCallTotalSupply"`
	EthCallOwnerBalance hexutil.Bytes  `json:"ethCallOwnerBalance"`
	Proof               AccountProof   `json:"proof"`
}

// The expected bytes are written by hand, so a layout mistake shared by EncodeStateProof and VerifyStateCapture still
// fails.
func TestEncodeStateProof(t *testing.T) {
	t.Parallel()
	p := AccountProof{
		AccountProof: []hexutil.Bytes{{0x01}, {0x02, 0x03}},
		StorageProof: []StorageProof{{Key: common.HexToHash("0x35"), Proof: []hexutil.Bytes{{0x04}}}},
	}
	want := hexBytes(t, "ea"+"c401820203"+"e4"+"e3"+"a0"+strings.Repeat("00", 31)+"35"+"c104")
	got, err := EncodeStateProof(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeStateProof =\n%x\nwant\n%x", got, want)
	}
}

// The owner holds nothing, so its slot is absent from storage and the proof shows it holds zero.
func TestVerifyStateCapture(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"ethereum-usd1-proof.json", "bsc-usd1-proof.json"} {
		f := loadStateFixture(t, name)
		proof, err := EncodeStateProof(f.Proof)
		if err != nil {
			t.Fatal(err)
		}
		for slot, want := range map[common.Hash]hexutil.Bytes{f.SupplySlot: f.EthCallTotalSupply, f.OwnerBalanceSlot: f.EthCallOwnerBalance} {
			got, err := VerifyStateCapture(f.StateRoot, f.Contract, slot, proof)
			if err != nil {
				t.Fatalf("%s slot %s: %v", name, slot, err)
			}
			if got.Cmp(new(big.Int).SetBytes(want)) != 0 {
				t.Errorf("%s slot %s = %s, eth_call says %s", name, slot, got, new(big.Int).SetBytes(want))
			}
		}
	}
}

func TestVerifyStateCaptureRejects(t *testing.T) {
	t.Parallel()
	f := loadStateFixture(t, "ethereum-usd1-proof.json")
	otherRoot := loadStateFixture(t, "bsc-usd1-proof.json").StateRoot
	cases := []struct {
		name      string
		alter     func(p *AccountProof)
		stateRoot common.Hash
		slot      common.Hash
		wantErr   error
	}{
		{"slot without an entry", func(*AccountProof) {}, f.StateRoot, common.HexToHash("0x34"), ErrSlotNotProven},
		{"another state root", func(*AccountProof) {}, otherRoot, f.SupplySlot, ErrProof},
		{"account node dropped", func(p *AccountProof) { p.AccountProof = p.AccountProof[:len(p.AccountProof)-1] }, f.StateRoot, f.SupplySlot, ErrProof},
		{"storage node dropped", func(p *AccountProof) {
			nodes := p.StorageProof[0].Proof
			p.StorageProof[0].Proof = nodes[:len(nodes)-1]
		}, f.StateRoot, f.SupplySlot, ErrProof},
	}
	for _, tc := range cases {
		p := loadStateFixture(t, "ethereum-usd1-proof.json").Proof
		tc.alter(&p)
		proof, err := EncodeStateProof(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyStateCapture(tc.stateRoot, f.Contract, tc.slot, proof); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: VerifyStateCapture = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
}

func loadStateFixture(t *testing.T, name string) stateFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var f stateFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}
