package rule

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/shinzonetwork/shinzo-evidence-codec/evm"
	"github.com/shinzonetwork/shinzo-evidence-codec/statement"
)

// vectorNode is what a node answered for one block, saved byte for byte: the block with its transactions, its receipts,
// eth_getProof for USD1's supply slot, and eth_call totalSupply, the last two at the block's hash.
type vectorNode struct {
	Chain       string           `json:"chain"`
	Block       json.RawMessage  `json:"block"`
	Receipts    types.Receipts   `json:"receipts"`
	StateProof  evm.AccountProof `json:"stateProof"`
	TotalSupply hexutil.Bytes    `json:"totalSupply"`
}

// vectorOutputs is what the codec writes for the block, for other implementations to check themselves against.
type vectorOutputs struct {
	RawHeader   hexutil.Bytes `json:"rawHeader"`
	Records     hexutil.Bytes `json:"records"`
	RecordsRoot hexutil.Bytes `json:"recordsRoot"`
	Proof       hexutil.Bytes `json:"proof"`
	StateProof  hexutil.Bytes `json:"stateProof"`
	Supply      string        `json:"supply"`
	Statement   hexutil.Bytes `json:"statement"`
}

// TestVectors checks one Ethereum and one BSC block end to end against what the node said: the raw header hashes to the
// block hash, the node's transactions and receipts rebuild the header's roots, the USD1 records verify against them, the
// proven supply equals eth_call, and the rule accepts the block. The codec's outputs must also equal the vector file.
func TestVectors(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"ethereum-26378186", "bsc-132610290"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			node := loadVectorNode(t, name)
			var block struct {
				Hash           common.Hash        `json:"hash"`
				Transactions   types.Transactions `json:"transactions"`
				MilliTimestamp *hexutil.Uint64    `json:"milliTimestamp"`
			}
			var header types.Header
			if err := json.Unmarshal(node.Block, &block); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(node.Block, &header); err != nil {
				t.Fatal(err)
			}
			raw, err := rlp.EncodeToBytes(&header)
			if err != nil {
				t.Fatal(err)
			}
			h, err := evm.HeaderFromRaw(raw)
			if err != nil {
				t.Fatal(err)
			}
			if h.Hash != block.Hash {
				t.Fatalf("raw header hashes to %s, the node's block hash is %s", h.Hash, block.Hash)
			}
			if types.DeriveSha(block.Transactions, trie.NewStackTrie(nil)) != h.TransactionsRoot ||
				types.DeriveSha(node.Receipts, trie.NewStackTrie(nil)) != h.ReceiptsRoot {
				t.Fatal("the node's transactions or receipts do not rebuild the header's roots")
			}
			ms, err := evm.BlockTime(node.Chain, h)
			if err != nil {
				t.Fatal(err)
			}
			if block.MilliTimestamp != nil && ms != uint64(*block.MilliTimestamp) {
				t.Fatalf("BlockTime = %d, the node's milliTimestamp is %d", ms, uint64(*block.MilliTimestamp))
			}

			records, indices := usd1Records(t, node.Receipts, block.Transactions)
			encoded, root, err := evm.EncodeRecords(records)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := evm.BuildProof(node.Receipts, block.Transactions, indices)
			if err != nil {
				t.Fatal(err)
			}
			if err := evm.VerifyRecords(h.ReceiptsRoot, h.TransactionsRoot, records, proof); err != nil {
				t.Fatal(err)
			}
			stateProof, err := evm.EncodeStateProof(node.StateProof)
			if err != nil {
				t.Fatal(err)
			}
			supply, err := evm.VerifyStateCapture(h.StateRoot, common.HexToAddress(usd1), common.HexToHash("0x35"), stateProof)
			if err != nil {
				t.Fatal(err)
			}
			if supply.Cmp(new(big.Int).SetBytes(node.TotalSupply)) != 0 {
				t.Fatalf("proven supply %s, eth_call totalSupply %s", supply, new(big.Int).SetBytes(node.TotalSupply))
			}

			s := statement.Statement{
				Chain: node.Chain, Number: h.Number, Hash: h.Hash.Hex(), ParentHash: h.ParentHash.Hex(),
				ParentNumber: h.Number - 1, Timestamp: ms, Status: statement.StatusFinalized, Extractor: "vectors",
				Filter: statement.FilterContractLog, HeaderHash: sha256.Sum256(raw), Items: uint64(len(node.Receipts)),
				Claims:   []statement.Claim{{Asset: usd1, Count: uint64(len(records)), Root: root}},
				Captures: []statement.Capture{{Asset: usd1, Value: supply.String(), ProofHash: sha256.Sum256(stateProof)}},
			}
			statementBytes, err := s.Encode()
			if err != nil {
				t.Fatal(err)
			}
			checkVectorAccepted(t, s, raw, encoded, proof, stateProof)

			got := vectorOutputs{
				RawHeader: raw, Records: encoded, RecordsRoot: root[:], Proof: proof, StateProof: stateProof,
				Supply: supply.String(), Statement: statementBytes,
			}
			if want := loadVectorOutputs(t, name); !reflect.DeepEqual(got, want) {
				b, _ := json.MarshalIndent(got, "", "  ")
				t.Fatalf("codec outputs differ from %s.json; they are now:\n%s", name, b)
			}
		})
	}
}

// usd1Records returns the records of the transactions with a log from USD1, encoded as a generator encodes them.
func usd1Records(t *testing.T, receipts types.Receipts, transactions types.Transactions) ([]evm.Record, []uint64) {
	t.Helper()
	var records []evm.Record
	var indices []uint64
	for i, r := range receipts {
		if !slices.ContainsFunc(r.Logs, func(l *types.Log) bool { return strings.EqualFold(l.Address.Hex()[2:], usd1) }) {
			continue
		}
		receipt, err := r.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		transaction, err := transactions[i].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, evm.Record{Index: uint64(i), Receipt: receipt, Transaction: transaction})
		indices = append(indices, uint64(i))
	}
	if len(records) == 0 {
		t.Fatal("the block has no USD1 record")
	}
	return records, indices
}

// checkVectorAccepted signs s with two keys and checks that the rule accepts the block from the documents a host would
// hold for it.
func checkVectorAccepted(t *testing.T, s statement.Statement, raw, records, proof, stateProof []byte) {
	t.Helper()
	var keys []*secp256k1.PrivateKey
	var listed []string
	for _, name := range []string{"vector signer 1", "vector signer 2"} {
		key := secp256k1.PrivKeyFromBytes(crypto.Keccak256([]byte(name)))
		keys = append(keys, key)
		listed = append(listed, sign(t, key, s).Signer)
	}
	c, err := New(Config{Chain: s.Chain, Signers: listed, Required: 2, Assets: []Asset{{ID: usd1, SupplySlot: "0x35"}}})
	if err != nil {
		t.Fatal(err)
	}
	v := c.Check(s.Number, &Block{Number: s.ParentNumber, Hash: s.ParentHash}, Documents{
		Attestations: []Attestation{sign(t, keys[0], s), sign(t, keys[1], s)},
		Headers:      []Header{{Hash: s.Hash, Raw: raw}},
		Evidence:     []Evidence{{BlockHash: s.Hash, Asset: usd1, Records: records, Proof: proof}},
		Captures:     []Capture{{BlockHash: s.Hash, Asset: usd1, Value: s.Captures[0].Value, Proof: stateProof}},
	})
	if !v.Accepted || v.Block.Hash != s.Hash {
		t.Fatalf("Check = accepted %v, reason %q, results %+v", v.Accepted, v.Reason, v.Results)
	}
}

func loadVectorNode(t *testing.T, name string) vectorNode {
	t.Helper()
	compressed, err := os.ReadFile(filepath.Join("..", "testdata", "vectors", name+".node.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	var node vectorNode
	if err := json.NewDecoder(z).Decode(&node); err != nil {
		t.Fatal(err)
	}
	return node
}

func loadVectorOutputs(t *testing.T, name string) vectorOutputs {
	t.Helper()
	var want vectorOutputs
	b, err := os.ReadFile(filepath.Join("..", "testdata", "vectors", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	return want
}
