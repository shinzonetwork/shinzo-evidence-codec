// Package evm encodes and verifies the evidence generators write for EVM chains.
package evm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb"

	"github.com/shinzonetwork/shinzo-evidence-codec/merkle"
)

// Errors returned by the record and proof functions.
var (
	ErrUnsorted        = errors.New("indices out of order or repeated")
	ErrIndexOutOfRange = errors.New("index past the last item in the block")
	ErrProof           = errors.New("proof is malformed or incomplete")
	ErrMismatch        = errors.New("record is not the item proven at its index")
)

// Record is the transaction at Index in a block and its receipt, both in their consensus encodings.
type Record struct {
	Index       uint64
	Receipt     []byte
	Transaction []byte
}

// proofNodes is the RLP form of a proof: the receipt-trie nodes, then the transaction-trie nodes.
type proofNodes struct {
	Receipts     [][]byte
	Transactions [][]byte
}

// EncodeRecords returns the RLP list of records and the Merkle root of the records' encodings. Records must be in
// ascending index order.
func EncodeRecords(records []Record) ([]byte, [sha256.Size]byte, error) {
	if err := checkOrder(records); err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	leaves := make([]rlp.RawValue, len(records))
	for i, r := range records {
		leaf, err := rlp.EncodeToBytes(r)
		if err != nil {
			return nil, [sha256.Size]byte{}, err
		}
		leaves[i] = leaf
	}
	encoded, err := rlp.EncodeToBytes(leaves)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return encoded, merkleRoot(leaves), nil
}

// DecodeRecords parses bytes written by EncodeRecords and returns the records and the Merkle root of their encodings.
func DecodeRecords(encoded []byte) ([]Record, [sha256.Size]byte, error) {
	var leaves []rlp.RawValue
	if err := rlp.DecodeBytes(encoded, &leaves); err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	records := make([]Record, len(leaves))
	for i, leaf := range leaves {
		if err := rlp.DecodeBytes(leaf, &records[i]); err != nil {
			return nil, [sha256.Size]byte{}, fmt.Errorf("record %d: %w", i, err)
		}
	}
	if err := checkOrder(records); err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return records, merkleRoot(leaves), nil
}

// BuildProof returns the proof of the receipts and transactions at indices, which must be ascending. Each node
// list keeps the first copy of a node shared by several indices.
func BuildProof(receipts, transactions types.DerivableList, indices []uint64) ([]byte, error) {
	for i := 1; i < len(indices); i++ {
		if indices[i] <= indices[i-1] {
			return nil, fmt.Errorf("index %d: %w", indices[i], ErrUnsorted)
		}
	}
	var nodes proofNodes
	var err error
	if nodes.Receipts, err = prove(receipts, indices); err != nil {
		return nil, fmt.Errorf("receipts: %w", err)
	}
	if nodes.Transactions, err = prove(transactions, indices); err != nil {
		return nil, fmt.Errorf("transactions: %w", err)
	}
	return rlp.EncodeToBytes(nodes)
}

// VerifyRecords checks that each record's receipt and transaction are the items at its index in the tries whose
// roots are receiptsRoot and transactionsRoot, using a proof from BuildProof.
func VerifyRecords(receiptsRoot, transactionsRoot common.Hash, records []Record, proof []byte) error {
	var nodes proofNodes
	if err := rlp.DecodeBytes(proof, &nodes); err != nil {
		return fmt.Errorf("%w: %w", ErrProof, err)
	}
	receiptNodes, transactionNodes := proofSet(nodes.Receipts), proofSet(nodes.Transactions)
	for _, r := range records {
		if err := verifyItem(receiptsRoot, receiptNodes, r.Index, r.Receipt); err != nil {
			return fmt.Errorf("receipt %d: %w", r.Index, err)
		}
		if err := verifyItem(transactionsRoot, transactionNodes, r.Index, r.Transaction); err != nil {
			return fmt.Errorf("transaction %d: %w", r.Index, err)
		}
	}
	return nil
}

func checkOrder(records []Record) error {
	for i := 1; i < len(records); i++ {
		if records[i].Index <= records[i-1].Index {
			return fmt.Errorf("index %d: %w", records[i].Index, ErrUnsorted)
		}
	}
	return nil
}

func merkleRoot(leaves []rlp.RawValue) [sha256.Size]byte {
	b := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		b[i] = leaf
	}
	return merkle.Root(b)
}

func prove(list types.DerivableList, indices []uint64) ([][]byte, error) {
	t, err := listTrie(list)
	if err != nil {
		return nil, err
	}
	nodes := trienode.NewProofSet()
	for _, index := range indices {
		if index >= uint64(list.Len()) { //nolint:gosec // a list length is never negative
			return nil, fmt.Errorf("%w: %d of %d", ErrIndexOutOfRange, index, list.Len())
		}
		if err := t.Prove(rlp.AppendUint64(nil, index), nodes); err != nil {
			return nil, fmt.Errorf("index %d: %w", index, err)
		}
	}
	return nodes.List(), nil
}

// listTrie returns the trie a header's transactions or receipts root is computed over: each item of list under its
// RLP-encoded position.
func listTrie(list types.DerivableList) (*trie.Trie, error) {
	t := trie.NewEmpty(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil))
	var buf bytes.Buffer
	for i := range list.Len() {
		buf.Reset()
		list.EncodeIndex(i, &buf)
		if err := t.Update(rlp.AppendUint64(nil, uint64(i)), bytes.Clone(buf.Bytes())); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func proofSet(nodes [][]byte) *trienode.ProofSet {
	set := trienode.NewProofSet()
	for _, n := range nodes {
		_ = set.Put(crypto.Keccak256(n), n) // ProofSet.Put always returns nil
	}
	return set
}

// verifyItem checks that nodes prove want at position index of the trie with the given root.
func verifyItem(root common.Hash, nodes *trienode.ProofSet, index uint64, want []byte) error {
	got, err := trie.VerifyProof(root, rlp.AppendUint64(nil, index), nodes)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProof, err)
	}
	// VerifyProof returns no value and no error when the proof shows the position is empty.
	if got == nil || !bytes.Equal(got, want) {
		return ErrMismatch
	}
	return nil
}
